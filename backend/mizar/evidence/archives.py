"""Safe archive expansion (DESIGN.md §6.1, §15).

Members are streamed straight into the evidence store and stored by hash,
never by name, so member names cannot write outside the store. Names are still
validated: traversal or absolute paths in an archive are reported, because an
investigator should know about them.

Single-stream compressors (gzip, bzip2, xz) are treated as one-member
archives, so logs.tar.gz is a gzip container holding a tar container.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import stat
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import IO, Any, BinaryIO, Protocol, cast

from mizar.core.errors import ErrorCode, MizarError
from mizar.evidence.store import CHUNK_BYTES, EvidenceStore, StoredBlob


class _Readable(Protocol):
    # read1 returns what one decompression step produced, so if the stream breaks,
    # only that step is lost (read(n) would discard up to n decompressed bytes).
    def read1(self, size: int = -1, /) -> bytes: ...


def _as_readable(stream: IO[bytes]) -> _Readable:
    # ZipExtFile and tarfile's member reader both implement read1(); the stdlib
    # stubs only declare IO[bytes].
    if not hasattr(stream, "read1"):
        raise TypeError(f"{type(stream).__name__} has no read1()")
    return cast(_Readable, stream)


class ContainerType(StrEnum):
    ZIP = "zip"
    TAR = "tar"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"


# Archive formats recognized but not expanded in v1.
_UNSUPPORTED_MAGIC = {
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"Rar!\x1a\x07": "rar",
    b"\x28\xb5\x2f\xfd": "zstd",
}

_SINGLE_STREAM_SUFFIXES = {
    ContainerType.GZIP: (".gz", ".gzip"),
    ContainerType.BZIP2: (".bz2",),
    ContainerType.XZ: (".xz",),
}
_TAR_SHORTHAND = {".tgz": ".tar", ".tbz2": ".tar", ".txz": ".tar"}


def detect_container(head: bytes) -> ContainerType | None:
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return ContainerType.ZIP
    if head.startswith(b"\x1f\x8b"):
        return ContainerType.GZIP
    if head.startswith(b"BZh") and len(head) >= 4 and head[3:4].isdigit():
        return ContainerType.BZIP2
    if head.startswith(b"\xfd7zXZ\x00"):
        return ContainerType.XZ
    if len(head) >= 262 and head[257:262] == b"ustar":
        return ContainerType.TAR
    return None


def detect_unsupported_archive(head: bytes) -> str | None:
    for magic, name in _UNSUPPORTED_MAGIC.items():
        if head.startswith(magic):
            return name
    return None


@dataclass
class ByteBudget:
    """Remaining uncompressed bytes the case may still store."""

    remaining: int


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int
    max_member_bytes: int
    max_compression_ratio: int
    ratio_floor_bytes: int


# Records a stored member in the database and returns its source_file_id.
# Called under the evidence store lock (see store.BlobWriter.commit).
RegisterMember = Callable[[str, StoredBlob, list[dict[str, Any]]], str]


@dataclass(frozen=True)
class ExtractedMember:
    member_path: str
    blob: StoredBlob
    source_file_id: str


@dataclass(frozen=True)
class MemberProblem:
    code: ErrorCode
    message: str
    details: dict[str, Any]


ExpansionItem = ExtractedMember | MemberProblem

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def check_member_path(raw: str) -> tuple[str | None, MemberProblem | None]:
    """Return (normalized path, None) or (None, problem)."""
    shown = raw[:500]
    if "\x00" in raw:
        return None, MemberProblem(
            ErrorCode.ARCHIVE_PATH_TRAVERSAL, "Member name contains a NUL byte.", {"name": shown}
        )
    path = raw.replace("\\", "/")
    if path.startswith("/") or _DRIVE_PREFIX.match(path):
        return None, MemberProblem(
            ErrorCode.ARCHIVE_PATH_TRAVERSAL, "Member uses an absolute path.", {"name": shown}
        )
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if ".." in parts:
        return None, MemberProblem(
            ErrorCode.ARCHIVE_PATH_TRAVERSAL,
            "Member path escapes the archive root ('..').",
            {"name": shown},
        )
    if not parts:
        return None, MemberProblem(
            ErrorCode.ARCHIVE_PATH_TRAVERSAL, "Member has an empty name.", {"name": shown}
        )
    return "/".join(parts), None


def _limit_error(limits: ArchiveLimits, budget: ByteBudget) -> Callable[[int], MizarError]:
    def build(limit: int) -> MizarError:
        if limit >= limits.max_member_bytes:
            return MizarError(
                ErrorCode.FILE_TOO_LARGE,
                "Archive member exceeds the per-file size limit.",
                details={"limit_bytes": limit},
            )
        return MizarError(
            ErrorCode.CASE_BUDGET_EXCEEDED,
            "Archive member exceeds the remaining case storage budget.",
            details={"remaining_bytes": budget.remaining},
        )

    return build


_STREAM_ERRORS: tuple[type[BaseException], ...] = (
    EOFError,
    OSError,
    zlib.error,
    lzma.LZMAError,
    zipfile.BadZipFile,
    tarfile.TarError,
)


def _copy_member(
    member_path: str,
    source: _Readable,
    store: EvidenceStore,
    register: RegisterMember,
    *,
    compressed_size: int | None,
    limits: ArchiveLimits,
    budget: ByteBudget,
) -> ExtractedMember:
    """Stream one member into the store, enforcing size, budget and ratio limits.

    A read error part-way through (truncated or corrupt compressed data) keeps
    what was recovered and returns an ARCHIVE_TRUNCATED warning: partial logs
    are still evidence. Limit violations discard the member.
    """
    max_bytes = min(limits.max_member_bytes, budget.remaining)
    warnings: list[dict[str, Any]] = []
    with store.writer(max_bytes, _limit_error(limits, budget)) as writer:
        while True:
            try:
                chunk = source.read1(CHUNK_BYTES)
            except _STREAM_ERRORS as exc:
                if writer.size_bytes == 0:
                    writer.abort()
                    raise MizarError(
                        ErrorCode.ARCHIVE_CORRUPT,
                        "The compressed data could not be read.",
                        details={"error": type(exc).__name__},
                    ) from exc
                warnings.append(
                    {
                        "level": "warning",
                        "code": ErrorCode.ARCHIVE_TRUNCATED.value,
                        "message": "Compressed data ended or failed part-way; "
                        "the recovered portion was kept.",
                        "details": {
                            "recovered_bytes": writer.size_bytes,
                            "error": type(exc).__name__,
                        },
                    }
                )
                break
            if not chunk:
                break
            writer.write(chunk)
            written = writer.size_bytes
            if (
                compressed_size is not None
                and written > limits.ratio_floor_bytes
                and written > limits.max_compression_ratio * max(compressed_size, 1)
            ):
                writer.abort()
                raise MizarError(
                    ErrorCode.ARCHIVE_BOMB_SUSPECTED,
                    "Member decompresses beyond the allowed compression ratio.",
                    details={
                        "compressed_bytes": compressed_size,
                        "max_ratio": limits.max_compression_ratio,
                    },
                )
        member = writer.commit(
            lambda blob: ExtractedMember(member_path, blob, register(member_path, blob, warnings))
        )
    budget.remaining -= member.blob.size_bytes
    return member


_FATAL_CODES = frozenset(
    {ErrorCode.STORAGE_FULL, ErrorCode.HASH_IO_ERROR, ErrorCode.EVIDENCE_INTEGRITY_MISMATCH}
)


def _member_from_stream(
    member_path: str,
    source: _Readable,
    store: EvidenceStore,
    register: RegisterMember,
    *,
    compressed_size: int | None,
    limits: ArchiveLimits,
    budget: ByteBudget,
) -> ExpansionItem:
    try:
        return _copy_member(
            member_path,
            source,
            store,
            register,
            compressed_size=compressed_size,
            limits=limits,
            budget=budget,
        )
    except MizarError as exc:
        if exc.code in _FATAL_CODES:
            raise
        return MemberProblem(exc.code, exc.message, {"name": member_path, **exc.details})


def single_stream_member_name(container: ContainerType, archive_name: str, head: bytes) -> str:
    """Name for the content of a gzip/bzip2/xz file."""
    if container is ContainerType.GZIP:
        embedded = _gzip_embedded_name(head)
        if embedded:
            return embedded
    lowered = archive_name.lower()
    for shorthand, replacement in _TAR_SHORTHAND.items():
        if lowered.endswith(shorthand):
            return archive_name[: -len(shorthand)] + replacement
    for suffix in _SINGLE_STREAM_SUFFIXES.get(container, ()):
        if lowered.endswith(suffix) and len(archive_name) > len(suffix):
            return archive_name[: -len(suffix)]
    return archive_name + ".decompressed"


def _gzip_embedded_name(head: bytes) -> str | None:
    """Original filename from the gzip header (FNAME), if present."""
    if len(head) < 10 or not head[3] & 0x08:
        return None
    position = 10
    if head[3] & 0x04:  # FEXTRA
        if len(head) < 12:
            return None
        position += 2 + int.from_bytes(head[10:12], "little")
    end = head.find(b"\x00", position)
    if end == -1 or end == position:
        return None
    name = head[position:end].decode("latin-1")
    normalized, problem = check_member_path(name)
    return normalized.rsplit("/", 1)[-1] if problem is None and normalized else None


def expand(
    store: EvidenceStore,
    container: ContainerType,
    blob_sha256: str,
    archive_name: str,
    *,
    archive_size: int,
    limits: ArchiveLimits,
    budget: ByteBudget,
    register: RegisterMember,
) -> Iterator[ExpansionItem]:
    """Yield each member as an ExtractedMember or a MemberProblem.

    Raises MizarError(ARCHIVE_CORRUPT) if the archive cannot be read at all.
    """
    if container is ContainerType.ZIP:
        yield from _expand_zip(store, blob_sha256, limits, budget, register)
    elif container is ContainerType.TAR:
        yield from _expand_tar(store, blob_sha256, limits, budget, register)
    else:
        yield from _expand_single(
            store, container, blob_sha256, archive_name, archive_size, limits, budget, register
        )


def _corrupt(container: ContainerType, exc: BaseException) -> MizarError:
    return MizarError(
        ErrorCode.ARCHIVE_CORRUPT,
        f"The {container.value} archive could not be read.",
        details={"error": type(exc).__name__},
    )


def _member_limit_problem(limits: ArchiveLimits) -> MemberProblem:
    return MemberProblem(
        ErrorCode.ARCHIVE_MEMBER_LIMIT,
        "The archive has more members than allowed; the rest were not extracted.",
        {"max_members": limits.max_members},
    )


def _expand_zip(
    store: EvidenceStore,
    sha256: str,
    limits: ArchiveLimits,
    budget: ByteBudget,
    register: RegisterMember,
) -> Iterator[ExpansionItem]:
    with store.open(sha256) as raw:
        try:
            archive = zipfile.ZipFile(raw)
        except (zipfile.BadZipFile, OSError, EOFError) as exc:
            raise _corrupt(ContainerType.ZIP, exc) from exc
        with archive:
            extracted = 0
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if extracted >= limits.max_members:
                    yield _member_limit_problem(limits)
                    return
                path, problem = check_member_path(info.filename)
                if problem is not None:
                    yield problem
                    continue
                assert path is not None
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    yield MemberProblem(
                        ErrorCode.ARCHIVE_MEMBER_UNSUPPORTED,
                        "Symbolic link members are not extracted.",
                        {"name": path},
                    )
                    continue
                if info.flag_bits & 0x1:
                    yield MemberProblem(
                        ErrorCode.ARCHIVE_ENCRYPTED,
                        "Encrypted members cannot be extracted.",
                        {"name": path},
                    )
                    continue
                try:
                    source = archive.open(info)
                except NotImplementedError:
                    yield MemberProblem(
                        ErrorCode.ARCHIVE_MEMBER_UNSUPPORTED,
                        "The member uses an unsupported compression method.",
                        {"name": path, "compress_type": info.compress_type},
                    )
                    continue
                except (zipfile.BadZipFile, OSError) as exc:
                    yield MemberProblem(
                        ErrorCode.ARCHIVE_CORRUPT,
                        "The member's header is corrupt.",
                        {"name": path, "error": type(exc).__name__},
                    )
                    continue
                with source:
                    extracted += 1
                    yield _member_from_stream(
                        path,
                        _as_readable(source),
                        store,
                        register,
                        compressed_size=info.compress_size,
                        limits=limits,
                        budget=budget,
                    )


def _expand_tar(
    store: EvidenceStore,
    sha256: str,
    limits: ArchiveLimits,
    budget: ByteBudget,
    register: RegisterMember,
) -> Iterator[ExpansionItem]:
    with store.open(sha256) as raw:
        try:
            # Plain tar only: compression is a separate container level.
            archive = tarfile.open(fileobj=raw, mode="r:")  # noqa: SIM115 (closed below)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise _corrupt(ContainerType.TAR, exc) from exc
        with archive:
            extracted = 0
            try:
                for info in archive:
                    if info.isdir():
                        continue
                    if extracted >= limits.max_members:
                        yield _member_limit_problem(limits)
                        return
                    path, problem = check_member_path(info.name)
                    if problem is not None:
                        yield problem
                        continue
                    assert path is not None
                    if not info.isreg():
                        yield MemberProblem(
                            ErrorCode.ARCHIVE_MEMBER_UNSUPPORTED,
                            "Links, devices and FIFOs are not extracted.",
                            {"name": path, "tar_type": info.type.decode("latin-1")},
                        )
                        continue
                    source = archive.extractfile(info)
                    if source is None:
                        continue
                    with source:
                        extracted += 1
                        yield _member_from_stream(
                            path,
                            _as_readable(source),
                            store,
                            register,
                            compressed_size=None,
                            limits=limits,
                            budget=budget,
                        )
            except tarfile.TarError as exc:
                yield MemberProblem(
                    ErrorCode.ARCHIVE_TRUNCATED,
                    "The tar archive ends unexpectedly; later members may be missing.",
                    {"error": type(exc).__name__},
                )


def _decompressor(container: ContainerType, raw: BinaryIO) -> io.BufferedIOBase:
    if container is ContainerType.GZIP:
        return gzip.GzipFile(fileobj=raw, mode="rb")
    if container is ContainerType.BZIP2:
        return bz2.BZ2File(raw, mode="rb")
    return lzma.LZMAFile(raw, mode="rb")


def _expand_single(
    store: EvidenceStore,
    container: ContainerType,
    sha256: str,
    archive_name: str,
    archive_size: int,
    limits: ArchiveLimits,
    budget: ByteBudget,
    register: RegisterMember,
) -> Iterator[ExpansionItem]:
    head = store.read_head(sha256, 4096)
    name = single_stream_member_name(container, archive_name, head)
    with store.open(sha256) as raw, _decompressor(container, raw) as source:
        yield _member_from_stream(
            name,
            source,
            store,
            register,
            compressed_size=archive_size,
            limits=limits,
            budget=budget,
        )
