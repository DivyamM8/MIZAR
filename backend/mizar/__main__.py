"""Command line entry point: `mizar serve`, `mizar worker`, `mizar migrate`."""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import signal
import subprocess
import sys
import threading
from types import FrameType

from pydantic import ValidationError

from mizar.core.config import Settings
from mizar.core.logging import configure_logging
from mizar.db.engine import make_engine, upgrade_db
from mizar.evidence.store import EvidenceStore

log = logging.getLogger("mizar")

_WORKER_RESTART_DELAY = 2.0
_WORKER_STOP_TIMEOUT = 15.0
# Set by `mizar serve` for its worker: the worker stops if that process goes away.
_SUPERVISOR_ENV = "MIZAR_SUPERVISOR_PID"


def _load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as exc:
        print(f"Invalid MIZAR configuration:\n{exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _prepare(settings: Settings) -> None:
    # Everything MIZAR writes (database, evidence, exports) is private to this user.
    os.umask(0o077)
    configure_logging(settings.log_level)
    settings.ensure_directories()


def _store(settings: Settings) -> EvidenceStore:
    return EvidenceStore(settings.evidence_dir, settings.staging_dir, settings.min_free_disk_bytes)


def cmd_migrate(settings: Settings) -> int:
    _prepare(settings)
    upgrade_db(make_engine(settings.db_path))
    log.info("database is at the latest revision")
    return 0


def cmd_worker(settings: Settings) -> int:
    import mizar.jobs.handlers  # noqa: F401  (registers job handlers)
    from mizar.jobs.worker import WorkerDeps, run_worker

    _prepare(settings)
    engine = make_engine(settings.db_path)
    upgrade_db(engine)
    stop = threading.Event()

    def handle_signal(signum: int, _frame: FrameType | None) -> None:
        log.info("worker received signal %d, stopping", signum)
        stop.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    supervisor = os.environ.get(_SUPERVISOR_ENV)
    if supervisor:
        threading.Thread(
            target=_stop_when_orphaned, args=(int(supervisor), stop), daemon=True
        ).start()
    run_worker(WorkerDeps(settings, engine, _store(settings)), stop)
    return 0


def _stop_when_orphaned(supervisor_pid: int, stop: threading.Event) -> None:
    """Stop the worker if `mizar serve` died without stopping it (e.g. killed with SIGKILL)."""
    while not stop.wait(1.0):
        if os.getppid() != supervisor_pid:
            log.warning("mizar serve is no longer running; worker stopping")
            stop.set()


class _WorkerSupervisor:
    """Runs `mizar worker` as a child process and restarts it if it dies."""

    def __init__(self) -> None:
        self._stopping = threading.Event()
        self._process: subprocess.Popen[bytes] | None = None
        self._thread = threading.Thread(target=self._run, name="worker-supervisor", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while not self._stopping.is_set():
            self._process = subprocess.Popen(
                [sys.executable, "-m", "mizar", "worker"],
                env={**os.environ, _SUPERVISOR_ENV: str(os.getpid())},
            )
            code = self._process.wait()
            if self._stopping.is_set():
                return
            log.error("worker exited unexpectedly (code %s); restarting", code)
            self._stopping.wait(_WORKER_RESTART_DELAY)

    def stop(self) -> None:
        self._stopping.set()
        process = self._process
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=_WORKER_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            log.error("worker did not stop in time; killing it")
            process.kill()
            process.wait()


def cmd_serve(settings: Settings) -> int:
    import uvicorn

    from mizar.api.app import create_app

    _prepare(settings)
    engine = make_engine(settings.db_path)
    upgrade_db(engine)
    # Nothing is writing yet, so leftovers are from an interrupted earlier run.
    removed = _store(settings).clear_staging()
    if removed:
        log.warning("removed %d incomplete staging file(s) from an earlier run", removed)

    # A fresh token per launch. MIZAR_API_TOKEN overrides it for development tooling.
    api_token = os.environ.get("MIZAR_API_TOKEN") or secrets.token_urlsafe(32)
    app = create_app(settings, engine, api_token)
    supervisor = _WorkerSupervisor()
    supervisor.start()

    # uvicorn re-raises a SIGTERM it handled once it has shut down; without this the default
    # action would end the process before the worker is stopped below.
    def exit_on_sigterm(_signum: int, _frame: FrameType | None) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, exit_on_sigterm)
    log.info("MIZAR listening on http://%s:%d", settings.host, settings.port)
    try:
        uvicorn.run(app, host=settings.host, port=settings.port, log_config=None)
    finally:
        supervisor.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mizar", description="MIZAR log analyzer")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the local web application (starts the worker too)")
    sub.add_parser("worker", help="run the background job worker only")
    sub.add_parser("migrate", help="apply database migrations")
    args = parser.parse_args(argv)

    settings = _load_settings()
    commands = {"serve": cmd_serve, "worker": cmd_worker, "migrate": cmd_migrate}
    return commands[args.command](settings)


if __name__ == "__main__":
    raise SystemExit(main())
