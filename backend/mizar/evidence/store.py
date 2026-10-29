"""Immutable, content-addressed evidence store (DESIGN.md §6).

Blobs live at evidence/sha256/ab/cd/<sha256>, are written once through a
staging file while being hashed, and are made read-only. Identical content is
stored once; callers track which source files reference which blob.

Concurrency: the API process and the worker process both add blobs, and case
deletion removes them. A cross-process lock (flock on evidence/.lock) is held
while a blob is committed *together with* the database row that references it,
and while deletion checks references, so a blob can never be deleted between
being stored and being referenced.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self, TypeVar

from mizar.core.errors import ErrorCode, MizarError

CHUNK_BYTES = 1024 * 1024
_FREE_SPACE_CHECK_INTERVAL = 64 * CHUNK_BYTES
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

T = TypeVar("T")


@dataclass(frozen=True)
class StoredBlob:
    sha256: str
    size_bytes: int
    already_existed: bool


class VerifyStatus(StrEnum):
    VERIFIED = "verified"
    INTEGRITY_FAILED = "integrity_failed"
    MISSING = "missing"


@dataclass(frozen=True)
class VerifyResult:
    status: VerifyStatus
    expected_sha256: str
    actual_sha256: str | None


def hash_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK_BYTES):
        digest.update(chunk)
    return digest.hexdigest()


class EvidenceStore:
    def __init__(self, evidence_dir: Path, staging_dir: Path, min_free_bytes: int) -> None:
        self.evidence_dir = evidence_dir
        self.staging_dir = staging_dir
        self.min_free_bytes = min_free_bytes

    def blob_path(self, sha256: str) -> Path:
        if not _SHA256_HEX.match(sha256):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return self.evidence_dir / "sha256" / sha256[:2] / sha256[2:4] / sha256

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Exclusive lock across threads and processes for add/delete decisions."""
        self.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (self.evidence_dir / ".lock").open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def exists(self, sha256: str) -> bool:
        return self.blob_path(sha256).is_file()

    def writer(self, max_bytes: int, limit_error: Callable[[int], MizarError]) -> BlobWriter:
        """Start writing a new blob. limit_error builds the error raised past max_bytes."""
        return BlobWriter(self, max_bytes, limit_error)

    def open(self, sha256: str) -> BinaryIO:
        try:
            return self.blob_path(sha256).open("rb")
        except FileNotFoundError as exc:
            raise MizarError(
                ErrorCode.EVIDENCE_MISSING,
                "An evidence file is missing from the evidence store.",
                details={"sha256": sha256},
            ) from exc

    def read_head(self, sha256: str, size: int) -> bytes:
        with self.open(sha256) as stream:
            return stream.read(size)

    def verify(self, sha256: str) -> VerifyResult:
        try:
            with self.blob_path(sha256).open("rb") as stream:
                actual = hash_stream(stream)
        except FileNotFoundError:
            return VerifyResult(VerifyStatus.MISSING, sha256, None)
        status = VerifyStatus.VERIFIED if actual == sha256 else VerifyStatus.INTEGRITY_FAILED
        return VerifyResult(status, sha256, actual)

    def delete(self, sha256: str) -> bool:
        """Remove a blob. Call under lock(), after checking nothing references it."""
        try:
            self.blob_path(sha256).unlink()
        except FileNotFoundError:
            return False
        return True

    def clear_staging(self) -> int:
        """Remove leftover staging files. Only call while nothing is writing."""
        removed = 0
        for path in self.staging_dir.glob("blob-*"):
            path.unlink(missing_ok=True)
            removed += 1
        return removed

    def _check_free_space(self) -> None:
        if shutil.disk_usage(self.staging_dir).free < self.min_free_bytes:
            raise MizarError(
                ErrorCode.STORAGE_FULL,
                "Not enough free disk space to store more evidence.",
                details={"min_free_bytes": self.min_free_bytes},
            )


class BlobWriter:
    """Streams bytes into a staging file while hashing; commit() moves it into the store.

    Any failure removes the staging file. Use as a context manager so an
    exception before commit() also cleans up.
    """

    def __init__(
        self, store: EvidenceStore, max_bytes: int, limit_error: Callable[[int], MizarError]
    ) -> None:
        store._check_free_space()
        self._store = store
        self._max_bytes = max_bytes
        self._limit_error = limit_error
        fd, name = tempfile.mkstemp(dir=store.staging_dir, prefix="blob-")
        self._path = Path(name)
        self._file = os.fdopen(fd, "wb")
        self._digest = hashlib.sha256()
        self._size = 0
        self._next_space_check = _FREE_SPACE_CHECK_INTERVAL
        self._finished = False

    @property
    def size_bytes(self) -> int:
        return self._size

    def write(self, data: bytes) -> None:
        if self._finished:
            raise RuntimeError("writer already finished")
        if self._size + len(data) > self._max_bytes:
            self.abort()
            raise self._limit_error(self._max_bytes)
        try:
            self._file.write(data)
        except OSError as exc:
            self.abort()
            raise _storage_error(exc) from exc
        self._digest.update(data)
        self._size += len(data)
        if self._size >= self._next_space_check:
            self._next_space_check += _FREE_SPACE_CHECK_INTERVAL
            try:
                self._store._check_free_space()
            except MizarError:
                self.abort()
                raise

    def commit(self, register: Callable[[StoredBlob], T]) -> T:
        """Move the blob into the store and call register(blob) under the store lock.

        register records the blob in the database. If it raises, a blob that
        this commit created is removed again; a pre-existing blob is left alone.
        """
        if self._finished:
            raise RuntimeError("writer already finished")
        try:
            self._file.flush()
            os.fsync(self._file.fileno())
            self._file.close()
        except OSError as exc:
            self.abort()
            raise _storage_error(exc) from exc
        sha256 = self._digest.hexdigest()
        destination = self._store.blob_path(sha256)
        with self._store.lock():
            existed = False
            try:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(self._path, 0o444)
                # link() never overwrites, so an existing blob (same content) is kept as is.
                os.link(self._path, destination)
            except FileExistsError:
                existed = True
            except OSError as exc:
                self.abort()
                raise _storage_error(exc) from exc
            finally:
                self._path.unlink(missing_ok=True)
                self._finished = True
            if existed and self._store.verify(sha256).status is not VerifyStatus.VERIFIED:
                # Never point a new record at a stored copy that no longer matches its hash.
                raise MizarError(
                    ErrorCode.EVIDENCE_INTEGRITY_MISMATCH,
                    "The stored copy of this content fails hash verification.",
                    details={"sha256": sha256},
                )
            blob = StoredBlob(sha256=sha256, size_bytes=self._size, already_existed=existed)
            try:
                return register(blob)
            except BaseException:
                if not existed:
                    self._store.delete(sha256)
                raise

    def abort(self) -> None:
        if self._finished:
            return
        self._finished = True
        try:
            self._file.close()
        finally:
            self._path.unlink(missing_ok=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self.abort()


def _storage_error(exc: OSError) -> MizarError:
    if exc.errno == errno.ENOSPC:
        return MizarError(ErrorCode.STORAGE_FULL, "The disk is full; evidence was not stored.")
    return MizarError(
        ErrorCode.HASH_IO_ERROR,
        "An I/O error occurred while storing evidence.",
        details={"errno": exc.errno},
    )
