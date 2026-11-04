"""Runtime configuration, read from MIZAR_* environment variables."""

from __future__ import annotations

import ipaddress
from functools import cached_property
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

GIB = 1024**3


def _default_data_dir() -> Path:
    return Path.home() / ".local" / "share" / "mizar"


def _default_frontend_dir() -> Path:
    # An installed package carries the UI in mizar/web (scripts/build.sh); a source
    # checkout uses frontend/dist next to the backend.
    packaged = Path(__file__).resolve().parents[1] / "web"
    if (packaged / "index.html").is_file():
        return packaged
    return Path(__file__).resolve().parents[3] / "frontend" / "dist"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MIZAR_", frozen=True)

    data_dir: Path = Field(default_factory=_default_data_dir)

    # Single-analyst local tool (DESIGN.md D4): only loopback binds are accepted.
    host: str = "127.0.0.1"
    port: int = Field(default=8730, ge=1, le=65535)
    # Host header values accepted (DNS-rebinding protection, DESIGN.md §15).
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]")
    # Extra browser origins allowed to call the API, e.g. the Vite dev server.
    extra_allowed_origins: tuple[str, ...] = ()

    # Limits (DESIGN.md D11).
    max_file_bytes: int = Field(default=2 * GIB, gt=0)
    max_case_uncompressed_bytes: int = Field(default=20 * GIB, gt=0)
    max_archive_members: int = Field(default=10_000, gt=0)
    # Container nesting levels expanded, e.g. logs.tar.gz -> auth.log.2.gz is 3.
    max_archive_depth: int = Field(default=3, ge=0)
    max_compression_ratio: int = Field(default=100, gt=0)
    # The ratio check applies once a member has produced this many bytes, because
    # small, repetitive log files legitimately compress far beyond 100:1.
    compression_ratio_floor_bytes: int = Field(default=10 * 1024**2, ge=0)
    # Uploads and extraction stop before free disk space drops below this.
    min_free_disk_bytes: int = Field(default=1 * GIB, ge=0)
    # A job running longer is stopped and recorded as JOB_TIMEOUT, so input that hangs a
    # parser cannot block the queue (DESIGN.md §15). Measured: parsing a 2 GB case takes
    # well under an hour.
    job_timeout_seconds: int = Field(default=6 * 3600, ge=60)

    log_level: str = "INFO"
    # Built web UI (npm run build). Missing: the API still runs and "/" explains how to build it.
    frontend_dir: Path = Field(default_factory=_default_frontend_dir)

    @field_validator("host")
    @classmethod
    def _host_must_be_loopback(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"host must be a loopback IP address, got {value!r}") from exc
        if not address.is_loopback:
            raise ValueError(
                f"host must be a loopback address (MIZAR is localhost-only), got {value!r}"
            )
        return value

    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, value: str) -> str:
        upper = value.upper()
        if upper not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid log level {value!r}")
        return upper

    @cached_property
    def db_path(self) -> Path:
        return self.data_dir / "mizar.db"

    @cached_property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @cached_property
    def staging_dir(self) -> Path:
        return self.data_dir / "staging"

    @cached_property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    @cached_property
    def allowed_origins(self) -> frozenset[str]:
        origins = {f"http://{host}:{self.port}" for host in self.allowed_hosts}
        return frozenset(origins | set(self.extra_allowed_origins))

    def ensure_directories(self) -> None:
        """Create the data directory tree, readable only by the current user."""
        for path in (self.data_dir, self.evidence_dir, self.staging_dir, self.exports_dir):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
