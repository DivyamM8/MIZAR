import threading
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.db.tables import jobs
from mizar.jobs import queue
from mizar.jobs.worker import HANDLERS, JobContext, WorkerDeps, run_one


def _enqueue(engine: Engine, job_type: str = "test_job", payload: Any = None) -> str:
    with engine.begin() as conn:
        return queue.enqueue(conn, job_type, payload or {}, None)


@pytest.fixture
def handler(monkeypatch: pytest.MonkeyPatch) -> list[JobContext]:
    """Registers a 'test_job' handler whose behavior is set by payload['action']."""
    seen: list[JobContext] = []

    def run(ctx: JobContext) -> dict[str, Any]:
        seen.append(ctx)
        action = ctx.payload.get("action")
        if action == "domain_error":
            raise MizarError(ErrorCode.ARCHIVE_CORRUPT, "bad archive")
        if action == "crash":
            raise RuntimeError("secret detail")
        if action == "check_cancel":
            ctx.check_cancelled()
        return {"ok": True}

    monkeypatch.setitem(HANDLERS, "test_job", run)
    return seen


def test_claim_order_and_exclusivity(engine: Engine) -> None:
    first = _enqueue(engine)
    second = _enqueue(engine)
    claimed = queue.claim_next(engine)
    assert claimed is not None and claimed["job_id"] == first
    assert claimed["status"] == "running" and claimed["attempts"] == 1
    again = queue.claim_next(engine)
    assert again is not None and again["job_id"] == second
    assert queue.claim_next(engine) is None


def test_success(deps: WorkerDeps, handler: list[JobContext]) -> None:
    job_id = _enqueue(deps.engine)
    assert run_one(deps, threading.Event())
    job = queue.get_job(deps.engine, job_id)
    assert (job["status"], job["progress"], job["result"]) == ("succeeded", 1.0, {"ok": True})
    assert not run_one(deps, threading.Event())


def test_domain_error_is_recorded(deps: WorkerDeps, handler: list[JobContext]) -> None:
    job_id = _enqueue(deps.engine, payload={"action": "domain_error"})
    run_one(deps, threading.Event())
    job = queue.get_job(deps.engine, job_id)
    assert (job["status"], job["error_code"]) == ("failed", "ARCHIVE_CORRUPT")


def test_crash_hides_internals(deps: WorkerDeps, handler: list[JobContext]) -> None:
    job_id = _enqueue(deps.engine, payload={"action": "crash"})
    run_one(deps, threading.Event())
    job = queue.get_job(deps.engine, job_id)
    assert job["error_code"] == "INTERNAL_ERROR"
    assert "secret detail" not in job["error_message"]
    assert job_id in job["error_message"]


def test_unknown_job_type_fails(deps: WorkerDeps) -> None:
    job_id = _enqueue(deps.engine, job_type="no_such_type")
    run_one(deps, threading.Event())
    assert queue.get_job(deps.engine, job_id)["status"] == "failed"


def test_cancel_queued_job(deps: WorkerDeps, handler: list[JobContext]) -> None:
    job_id = _enqueue(deps.engine)
    assert queue.request_cancel(deps.engine, job_id)["status"] == "cancelled"
    assert not run_one(deps, threading.Event())
    assert handler == []


def test_cancel_running_job(deps: WorkerDeps, handler: list[JobContext]) -> None:
    job_id = _enqueue(deps.engine, payload={"action": "check_cancel"})
    with deps.engine.begin() as conn:
        conn.execute(update(jobs).values(cancel_requested=True))
    run_one(deps, threading.Event())
    job = queue.get_job(deps.engine, job_id)
    assert (job["status"], job["error_code"]) == ("cancelled", "JOB_CANCELLED")


def test_cancel_finished_job_is_refused(deps: WorkerDeps, handler: list[JobContext]) -> None:
    job_id = _enqueue(deps.engine)
    run_one(deps, threading.Event())
    with pytest.raises(MizarError) as info:
        queue.request_cancel(deps.engine, job_id)
    assert info.value.code is ErrorCode.JOB_NOT_CANCELLABLE


def test_worker_stop_requeues_job(deps: WorkerDeps, handler: list[JobContext]) -> None:
    job_id = _enqueue(deps.engine, payload={"action": "check_cancel"})
    stop = threading.Event()
    stop.set()
    run_one(deps, stop)
    assert queue.get_job(deps.engine, job_id)["status"] == "queued"


def test_recover_stale_requeues_then_fails(engine: Engine) -> None:
    retry = _enqueue(engine)
    exhausted = _enqueue(engine)
    queue.claim_next(engine)
    queue.claim_next(engine)
    with engine.begin() as conn:
        conn.execute(
            update(jobs).where(jobs.c.job_id == exhausted).values(attempts=queue.MAX_ATTEMPTS)
        )
    assert queue.recover_stale(engine, timedelta(0)) == (1, 1)
    assert queue.get_job(engine, retry)["status"] == "queued"
    failed = queue.get_job(engine, exhausted)
    assert (failed["status"], failed["error_code"]) == ("failed", "JOB_CRASHED")


def test_recent_heartbeat_is_not_stale(engine: Engine) -> None:
    _enqueue(engine)
    queue.claim_next(engine)
    assert queue.recover_stale(engine, timedelta(minutes=5)) == (0, 0)
