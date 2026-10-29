"""Background worker: claims jobs and runs their handlers (DESIGN.md D8)."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import Engine

from mizar.core.config import Settings
from mizar.core.errors import ErrorCode, MizarError
from mizar.evidence.store import EvidenceStore
from mizar.jobs import queue

log = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 5.0
_PROGRESS_MIN_INTERVAL = 0.5
_CANCEL_CHECK_INTERVAL = 1.0


class JobCancelled(Exception):
    """The analyst cancelled the running job."""


class WorkerStopping(Exception):
    """The worker is shutting down; the job goes back to the queue."""


@dataclass(frozen=True)
class WorkerDeps:
    settings: Settings
    engine: Engine
    store: EvidenceStore


class JobContext:
    def __init__(self, deps: WorkerDeps, job: dict[str, Any], stop: threading.Event) -> None:
        self.deps = deps
        self.job_id: str = job["job_id"]
        self.case_id: str | None = job["case_id"]
        self.payload: dict[str, Any] = job["payload"]
        self.attempt: int = job["attempts"]
        self._stop = stop
        self._last_progress = 0.0
        self._last_cancel_check = 0.0

    def check_cancelled(self) -> None:
        """Raise if the job should stop. Cheap to call often."""
        if self._stop.is_set():
            raise WorkerStopping
        now = time.monotonic()
        if now - self._last_cancel_check < _CANCEL_CHECK_INTERVAL:
            return
        self._last_cancel_check = now
        if queue.is_cancel_requested(self.deps.engine, self.job_id):
            raise JobCancelled

    def progress(self, fraction: float, message: str | None = None) -> None:
        self.check_cancelled()
        now = time.monotonic()
        if now - self._last_progress >= _PROGRESS_MIN_INTERVAL:
            self._last_progress = now
            queue.set_progress(self.deps.engine, self.job_id, fraction, message)


Handler = Callable[[JobContext], dict[str, Any]]
HANDLERS: dict[str, Handler] = {}


def register(job_type: str) -> Callable[[Handler], Handler]:
    def decorator(handler: Handler) -> Handler:
        if job_type in HANDLERS:
            raise ValueError(f"duplicate handler for job type {job_type!r}")
        HANDLERS[job_type] = handler
        return handler

    return decorator


def _heartbeat_loop(engine: Engine, job_id: str, done: threading.Event) -> None:
    while not done.wait(HEARTBEAT_SECONDS):
        try:
            queue.heartbeat(engine, job_id)
        except Exception:
            log.exception("heartbeat failed", extra={"job_id": job_id})


def run_one(deps: WorkerDeps, stop: threading.Event) -> bool:
    """Run the next queued job, if any. Returns False when the queue is empty."""
    job = queue.claim_next(deps.engine)
    if job is None:
        return False
    job_id = job["job_id"]
    extra = {"job_id": job_id, "case_id": job["case_id"]}
    log.info("job started: %s (attempt %d)", job["job_type"], job["attempts"], extra=extra)

    done = threading.Event()
    beat = threading.Thread(target=_heartbeat_loop, args=(deps.engine, job_id, done), daemon=True)
    beat.start()
    try:
        handler = HANDLERS.get(job["job_type"])
        if handler is None:
            queue.mark_failed(
                deps.engine,
                job_id,
                ErrorCode.INTERNAL_ERROR,
                f"No handler for job type {job['job_type']!r}.",
            )
            return True
        result = handler(JobContext(deps, job, stop))
        queue.mark_succeeded(deps.engine, job_id, result)
        log.info("job succeeded", extra=extra)
    except JobCancelled:
        queue.mark_cancelled(deps.engine, job_id)
        log.info("job cancelled", extra=extra)
    except WorkerStopping:
        queue.requeue(deps.engine, job_id)
        log.info("job requeued: worker stopping", extra=extra)
    except MizarError as exc:
        queue.mark_failed(deps.engine, job_id, exc.code, exc.message)
        log.warning("job failed: %s", exc.code.value, extra={**extra, "error_code": exc.code})
    except Exception:
        log.exception("job crashed", extra=extra)
        queue.mark_failed(
            deps.engine,
            job_id,
            ErrorCode.INTERNAL_ERROR,
            f"Unexpected error. See the application log for job {job_id}.",
        )
    finally:
        done.set()
        beat.join()
    return True


def run_worker(deps: WorkerDeps, stop: threading.Event, poll_seconds: float = 0.5) -> None:
    # Only one worker runs, so anything still 'running' at startup was orphaned.
    requeued, failed = queue.recover_stale(deps.engine, timedelta(0))
    if requeued or failed:
        log.warning("recovered orphaned jobs: %d requeued, %d failed", requeued, failed)
    log.info("worker ready")
    while not stop.is_set():
        try:
            ran = run_one(deps, stop)
        except Exception:
            # Database unavailable or similar: back off instead of spinning.
            log.exception("worker loop error")
            ran = False
        if not ran:
            stop.wait(poll_seconds)
    log.info("worker stopped")
