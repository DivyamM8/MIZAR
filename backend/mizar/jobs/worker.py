"""Background worker: claims jobs and runs their handlers (DESIGN.md D8)."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import Engine

from mizar.core.config import Settings
from mizar.core.errors import ErrorCode, MizarError
from mizar.db.bulk import ensure_event_indexes
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
# Called when a job of this type is stopped for running too long, to record the outcome
# on the records the job was working on (the handler itself gets no chance to).
AbortHook = Callable[[Engine, dict[str, Any], str], None]
ABORT_HOOKS: dict[str, AbortHook] = {}
# Exit status of a worker that stopped a timed-out job; `mizar serve` starts a new one.
EXIT_JOB_TIMEOUT = 75
_hard_exit: Callable[[int], None] = os._exit


def register(job_type: str) -> Callable[[Handler], Handler]:
    def decorator(handler: Handler) -> Handler:
        if job_type in HANDLERS:
            raise ValueError(f"duplicate handler for job type {job_type!r}")
        HANDLERS[job_type] = handler
        return handler

    return decorator


def register_abort(job_type: str) -> Callable[[AbortHook], AbortHook]:
    def decorator(hook: AbortHook) -> AbortHook:
        ABORT_HOOKS[job_type] = hook
        return hook

    return decorator


def _watchdog(deps: WorkerDeps, job: dict[str, Any], done: threading.Event) -> None:
    """Stop a job that runs past the time limit.

    A handler stuck in native code (e.g. a parser on hostile input) cannot be
    interrupted from Python, so the job is recorded as failed and the worker
    process exits; the supervisor in `mizar serve` starts a fresh worker. The job
    is not retried. SQLite rolls back whatever the handler had not committed.
    """
    limit = deps.settings.job_timeout_seconds
    if done.wait(limit):
        return
    job_id = job["job_id"]
    message = (
        f"The job ran longer than the {limit // 60}-minute limit and was stopped "
        "(MIZAR_JOB_TIMEOUT_SECONDS). The input may be malformed or too large."
    )
    log.error(
        "job timed out after %d s; restarting the worker",
        limit,
        extra={"job_id": job_id, "case_id": job["case_id"]},
    )
    try:
        queue.mark_failed(deps.engine, job_id, ErrorCode.JOB_TIMEOUT, message)
        hook = ABORT_HOOKS.get(job["job_type"])
        if hook is not None:
            hook(deps.engine, job, message)
    except Exception:
        log.exception("could not record the timeout", extra={"job_id": job_id})
    _hard_exit(EXIT_JOB_TIMEOUT)


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
    watchdog = threading.Thread(target=_watchdog, args=(deps, job, done), daemon=True)
    watchdog.start()
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
    # Indexes dropped by a bulk load that was interrupted (DESIGN.md D48).
    ensure_event_indexes(deps.engine)
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
