import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from typing import Any

import pytest

from mizar.core.errors import ErrorCode, MizarError
from mizar.evidence.archives import (
    ArchiveLimits,
    ByteBudget,
    ContainerType,
    ExpansionItem,
    ExtractedMember,
    MemberProblem,
    check_member_path,
    detect_container,
    detect_unsupported_archive,
    expand,
    single_stream_member_name,
)
from mizar.evidence.store import EvidenceStore, StoredBlob

LIMITS = ArchiveLimits(
    max_members=100,
    max_member_bytes=50 * 1024**2,
    max_compression_ratio=100,
    ratio_floor_bytes=1024**2,
)


def _never(limit: int) -> MizarError:
    raise AssertionError("limit unexpectedly hit")


class Registry:
    def __init__(self) -> None:
        self.members: dict[str, tuple[str, StoredBlob, list[dict[str, Any]]]] = {}

    def __call__(self, path: str, blob: StoredBlob, warnings: list[dict[str, Any]]) -> str:
        member_id = f"SF-{len(self.members) + 1}"
        self.members[member_id] = (path, blob, warnings)
        return member_id


def _expand(
    store: EvidenceStore,
    data: bytes,
    name: str = "evidence.bin",
    *,
    limits: ArchiveLimits = LIMITS,
    budget: int = 1 << 40,
    registry: Registry | None = None,
) -> list[ExpansionItem]:
    with store.writer(len(data) + 1, _never) as writer:
        writer.write(data)
        blob = writer.commit(lambda b: b)
    container = detect_container(data[:4096])
    assert container is not None
    return list(
        expand(
            store,
            container,
            blob.sha256,
            name,
            archive_size=blob.size_bytes,
            limits=limits,
            budget=ByteBudget(budget),
            register=registry or Registry(),
        )
    )


def _zip(entries: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _problems(items: list[ExpansionItem]) -> list[ErrorCode]:
    return [item.code for item in items if isinstance(item, MemberProblem)]


def _paths(items: list[ExpansionItem]) -> list[str]:
    return [item.member_path for item in items if isinstance(item, ExtractedMember)]


def test_zip_members_are_extracted_and_registered(store: EvidenceStore) -> None:
    registry = Registry()
    data = _zip({"var/log/auth.log": b"line1\n", "var/log/syslog": b"line2\n", "empty/": b""})
    items = _expand(store, data, registry=registry)
    assert sorted(_paths(items)) == ["var/log/auth.log", "var/log/syslog"]
    member = next(i for i in items if isinstance(i, ExtractedMember))
    assert member.source_file_id in registry.members
    assert store.blob_path(member.blob.sha256).read_bytes() in (b"line1\n", b"line2\n")


def test_zip_slip_names_are_reported_not_extracted(store: EvidenceStore) -> None:
    data = _zip(
        {
            "../../etc/cron.d/evil": b"x",
            "/etc/passwd": b"x",
            "C:\\Windows\\evil.dll": b"x",
            "ok.log": b"fine",
        }
    )
    items = _expand(store, data)
    assert _paths(items) == ["ok.log"]
    assert _problems(items) == [ErrorCode.ARCHIVE_PATH_TRAVERSAL] * 3


def test_zip_symlink_member_is_refused(store: EvidenceStore) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        link = zipfile.ZipInfo("link-to-shadow")
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "/etc/shadow")
    assert _problems(_expand(store, buffer.getvalue())) == [ErrorCode.ARCHIVE_MEMBER_UNSUPPORTED]


def test_zip_encrypted_member_is_reported(store: EvidenceStore) -> None:
    data = bytearray(_zip({"secret.log": b"data"}, compression=zipfile.ZIP_STORED))
    # Set the "encrypted" flag bit in the local and central directory headers.
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    data[local + 6] |= 0x01
    data[central + 8] |= 0x01
    assert _problems(_expand(store, bytes(data))) == [ErrorCode.ARCHIVE_ENCRYPTED]


def test_zip_bomb_is_stopped(store: EvidenceStore) -> None:
    data = _zip({"bomb.log": b"\x00" * (5 * 1024**2)})
    assert len(data) < 50_000
    items = _expand(store, data)
    assert _problems(items) == [ErrorCode.ARCHIVE_BOMB_SUSPECTED]
    assert list(store.staging_dir.iterdir()) == []


def test_repetitive_small_logs_are_not_mistaken_for_bombs(store: EvidenceStore) -> None:
    data = _zip({"repeat.log": b"Oct 29 12:00:00 host CRON[1]: tick\n" * 20_000})
    assert _problems(_expand(store, data)) == []


def test_member_count_limit(store: EvidenceStore) -> None:
    data = _zip({f"f{i}.log": b"x" for i in range(5)})
    limits = ArchiveLimits(3, LIMITS.max_member_bytes, 100, LIMITS.ratio_floor_bytes)
    items = _expand(store, data, limits=limits)
    assert len(_paths(items)) == 3
    assert _problems(items) == [ErrorCode.ARCHIVE_MEMBER_LIMIT]


def test_case_budget_limits_members(store: EvidenceStore) -> None:
    data = _zip({"a.log": b"x" * 10, "b.log": b"y" * 100})
    items = _expand(store, data, budget=50)
    assert _paths(items) == ["a.log"]
    assert _problems(items) == [ErrorCode.CASE_BUDGET_EXCEEDED]


def test_corrupt_zip_raises(store: EvidenceStore) -> None:
    with pytest.raises(MizarError) as info:
        _expand(store, b"PK\x03\x04" + b"\xff" * 200)
    assert info.value.code is ErrorCode.ARCHIVE_CORRUPT


def _gzip(content: bytes, embedded_name: str | None) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename=embedded_name or "", mode="wb", fileobj=buffer, mtime=0) as gz:
        gz.write(content)
    return buffer.getvalue()


def test_gzip_uses_embedded_name(store: EvidenceStore) -> None:
    items = _expand(store, _gzip(b"log\n", "auth.log.1"), "whatever.gz")
    assert _paths(items) == ["auth.log.1"]


def test_gzip_without_embedded_name_strips_suffix(store: EvidenceStore) -> None:
    items = _expand(store, _gzip(b"log\n", None), "auth.log.2.gz")
    assert _paths(items) == ["auth.log.2"]


def test_truncated_gzip_keeps_recovered_data_with_warning(store: EvidenceStore) -> None:
    content = b"".join(f"line {i} {i * 7919 % 10007}\n".encode() for i in range(50_000))
    data = _gzip(content, "big.log")
    registry = Registry()
    items = _expand(store, data[: len(data) // 2], registry=registry)
    assert _problems(items) == []
    (_, blob, warnings) = next(iter(registry.members.values()))
    assert 0 < blob.size_bytes < len(content)
    assert content.startswith(store.blob_path(blob.sha256).read_bytes())
    assert [w["code"] for w in warnings] == ["ARCHIVE_TRUNCATED"]


def test_unreadable_gzip_is_corrupt(store: EvidenceStore) -> None:
    items = _expand(store, b"\x1f\x8b\x08\x00" + b"\xff" * 100)
    assert _problems(items) == [ErrorCode.ARCHIVE_CORRUPT]


def test_bzip2_and_xz_are_single_member_containers(store: EvidenceStore) -> None:
    assert _paths(_expand(store, bz2.compress(b"a\n"), "x.log.bz2")) == ["x.log"]
    assert _paths(_expand(store, lzma.compress(b"a\n"), "x.log.xz")) == ["x.log"]


def _tar(build: Any) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        build(archive)
    return buffer.getvalue()


def _add(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    archive.addfile(info, io.BytesIO(content))


def test_tar_regular_files_only(store: EvidenceStore) -> None:
    def build(archive: tarfile.TarFile) -> None:
        _add(archive, "logs/auth.log", b"auth\n")
        _add(archive, "../escape.log", b"x")
        link = tarfile.TarInfo("logs/shadow")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        archive.addfile(link)
        device = tarfile.TarInfo("logs/sda")
        device.type = tarfile.BLKTYPE
        archive.addfile(device)

    items = _expand(store, _tar(build))
    assert _paths(items) == ["logs/auth.log"]
    assert _problems(items) == [
        ErrorCode.ARCHIVE_PATH_TRAVERSAL,
        ErrorCode.ARCHIVE_MEMBER_UNSUPPORTED,
        ErrorCode.ARCHIVE_MEMBER_UNSUPPORTED,
    ]


def test_container_detection() -> None:
    assert detect_container(_zip({"a": b"b"})) is ContainerType.ZIP
    assert detect_container(_gzip(b"a", None)) is ContainerType.GZIP
    assert detect_container(bz2.compress(b"a")) is ContainerType.BZIP2
    assert detect_container(lzma.compress(b"a")) is ContainerType.XZ
    assert detect_container(_tar(lambda t: _add(t, "a", b"b"))) is ContainerType.TAR
    assert detect_container(b"Oct 29 12:00:00 host sshd[1]: hi\n") is None
    assert detect_unsupported_archive(b"7z\xbc\xaf\x27\x1c\x00\x04") == "7z"
    assert detect_unsupported_archive(b"Rar!\x1a\x07\x01\x00") == "rar"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("var/log/auth.log", "var/log/auth.log"),
        ("./a//b/./c.log", "a/b/c.log"),
        ("dir\\file.log", "dir/file.log"),
        ("a/../../b", None),
        ("/abs", None),
        ("D:/x", None),
        ("", None),
        ("a\x00b", None),
    ],
)
def test_check_member_path(raw: str, expected: str | None) -> None:
    path, problem = check_member_path(raw)
    assert path == expected
    assert (problem is None) == (expected is not None)


def test_single_stream_names() -> None:
    assert single_stream_member_name(ContainerType.GZIP, "logs.tgz", b"") == "logs.tar"
    assert single_stream_member_name(ContainerType.GZIP, "logs.tar.gz", b"") == "logs.tar"
    assert single_stream_member_name(ContainerType.XZ, "noext", b"") == "noext.decompressed"
