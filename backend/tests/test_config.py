import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from mizar import __main__ as cli
from mizar.core import config
from mizar.core.config import Settings
from mizar.versions import MIZAR_VERSION


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


def test_packaged_ui_is_preferred(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    package = tmp_path / "site" / "mizar"
    (package / "core").mkdir(parents=True)
    monkeypatch.setattr(config, "__file__", str(package / "core" / "config.py"))
    source_checkout = config._default_frontend_dir()
    assert source_checkout.parts[-2:] == ("frontend", "dist")
    (package / "web").mkdir()
    (package / "web" / "index.html").write_text("<html></html>")
    assert config._default_frontend_dir() == package / "web"


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        cli.main(["--version"])
    assert exited.value.code == 0
    assert capsys.readouterr().out.strip() == f"MIZAR {MIZAR_VERSION}"


def test_open_data_directory_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o755)
    data.chmod(0o755)
    monkeypatch.setattr(cli, "configure_logging", lambda level: None)
    umask = os.umask(0o022)  # _prepare sets the process umask; restore it afterwards
    try:
        cli._prepare(Settings(data_dir=data))
        assert "accessible to other users" in caplog.text
        caplog.clear()
        data.chmod(0o700)
        cli._prepare(Settings(data_dir=data))
        assert "accessible to other users" not in caplog.text
    finally:
        os.umask(umask)
