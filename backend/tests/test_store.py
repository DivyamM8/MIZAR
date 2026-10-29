import hashlib
import os
import stat
import threading

import pytest

from mizar.core.errors import ErrorCode, MizarError
from mizar.evidence.store import EvidenceStore, StoredBlob, VerifyStatus


def _too_large(limit: int) -> MizarError:
    return MizarError(ErrorCode.FILE_TOO_LARGE, "too large", details={"limit_bytes": limit})


def _put(store: EvidenceStore, data: bytes, limit: int = 1 << 30) -> StoredBlob:
    with store.writer(limit, _too_large) as writer:
        for start in range(0, len(data), 7):
            writer.write(data[start : start + 7])
        return writer.commit(lambda blob: blob)


def test_blob_is_hashed_stored_read_only(store: EvidenceStore) -> None:
    data = b"Oct 29 12:00:01 host sshd[1]: Failed password\n" * 100
    blob = _put(store, data)
    assert blob.sha256 == hashlib.sha256(data).hexdigest()
    assert blob.size_bytes == len(data)
    assert not blob.already_existed
    path = store.blob_path(blob.sha256)
    assert path.read_bytes() == data
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    assert list(store.staging_dir.iterdir()) == []


def test_identical_content_is_stored_once(store: EvidenceStore) -> None:
    first = _put(store, b"same")
    second = _put(store, b"same")
    assert second.sha256 == first.sha256
    assert second.already_existed


def test_size_limit_aborts_and_cleans_staging(store: EvidenceStore) -> None:
    with pytest.raises(MizarError) as info:
        _put(store, b"x" * 100, limit=50)
    assert info.value.code is ErrorCode.FILE_TOO_LARGE
    assert list(store.staging_dir.iterdir()) == []


def test_exception_before_commit_cleans_staging(store: EvidenceStore) -> None:
    with pytest.raises(RuntimeError), store.writer(100, _too_large) as writer:
        writer.write(b"partial")
        raise RuntimeError("client went away")
    assert list(store.staging_dir.iterdir()) == []


def test_failed_registration_removes_new_blob(store: EvidenceStore) -> None:
    def register(blob: StoredBlob) -> None:
        raise MizarError(ErrorCode.CASE_NOT_FOUND, "case vanished")

    with pytest.raises(MizarError), store.writer(100, _too_large) as writer:
        writer.write(b"orphan")
        writer.commit(register)
    assert not store.exists(hashlib.sha256(b"orphan").hexdigest())


def test_failed_registration_keeps_preexisting_blob(store: EvidenceStore) -> None:
    existing = _put(store, b"shared")

    def register(blob: StoredBlob) -> None:
        raise MizarError(ErrorCode.CASE_NOT_FOUND, "case vanished")

    with pytest.raises(MizarError), store.writer(100, _too_large) as writer:
        writer.write(b"shared")
        writer.commit(register)
    assert store.exists(existing.sha256)


def test_verify_detects_tampering_and_missing(store: EvidenceStore) -> None:
    blob = _put(store, b"original evidence")
    assert store.verify(blob.sha256).status is VerifyStatus.VERIFIED

    path = store.blob_path(blob.sha256)
    os.chmod(path, 0o644)
    path.write_bytes(b"tampered evidence")
    result = store.verify(blob.sha256)
    assert result.status is VerifyStatus.INTEGRITY_FAILED
    assert result.actual_sha256 == hashlib.sha256(b"tampered evidence").hexdigest()

    path.unlink()
    assert store.verify(blob.sha256).status is VerifyStatus.MISSING


def test_reupload_onto_tampered_blob_is_refused(store: EvidenceStore) -> None:
    blob = _put(store, b"original")
    path = store.blob_path(blob.sha256)
    os.chmod(path, 0o644)
    path.write_bytes(b"tampered")
    with pytest.raises(MizarError) as info:
        _put(store, b"original")
    assert info.value.code is ErrorCode.EVIDENCE_INTEGRITY_MISMATCH


def test_free_space_floor_refuses_writes(store: EvidenceStore) -> None:
    strict = EvidenceStore(store.evidence_dir, store.staging_dir, min_free_bytes=1 << 62)
    with pytest.raises(MizarError) as info:
        strict.writer(100, _too_large)
    assert info.value.code is ErrorCode.STORAGE_FULL


def test_blob_path_rejects_non_hash(store: EvidenceStore) -> None:
    for bad in ("../../etc/passwd", "AB" * 32, "a" * 63):
        with pytest.raises(ValueError):
            store.blob_path(bad)


def test_lock_serializes_threads(store: EvidenceStore) -> None:
    order: list[str] = []
    entered = threading.Event()

    def holder() -> None:
        with store.lock():
            entered.set()
            order.append("holder-start")
            threading.Event().wait(0.2)
            order.append("holder-end")

    thread = threading.Thread(target=holder)
    thread.start()
    entered.wait()
    with store.lock():
        order.append("second")
    thread.join()
    assert order == ["holder-start", "holder-end", "second"]
