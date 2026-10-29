from pathlib import Path

import pytest
from pydantic import ValidationError

from mizar.core.config import Settings


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "example.com", "localhost"])
def test_non_loopback_host_is_refused(host: str, tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(data_dir=tmp_path, host=host)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1"])
def test_loopback_host_is_accepted(host: str, tmp_path: Path) -> None:
    assert Settings(data_dir=tmp_path, host=host).host == host


def test_defaults_match_design(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path)
    assert s.port == 8730
    assert s.max_file_bytes == 2 * 1024**3
    assert s.max_case_uncompressed_bytes == 20 * 1024**3
    assert s.max_archive_members == 10_000
    assert "http://127.0.0.1:8730" in s.allowed_origins


def test_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("MIZAR_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MIZAR_PORT", "9000")
    s = Settings()
    assert s.data_dir == tmp_path
    assert s.port == 9000


def test_data_directories_are_private(tmp_path: Path) -> None:
    s = Settings(data_dir=tmp_path / "d")
    s.ensure_directories()
    for path in (s.data_dir, s.evidence_dir, s.staging_dir, s.exports_dir):
        assert path.is_dir()
        assert path.stat().st_mode & 0o077 == 0
