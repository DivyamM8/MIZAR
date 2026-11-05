"""Loading large files without the random-key event indexes (DESIGN.md D48)."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, text

from mizar.db import bulk
from mizar.db.engine import _alembic_config, upgrade_db
from mizar.db.tables import event_group_members, events, raw_records
from mizar.ingest import parse as parse_module
from mizar.jobs.worker import JobCancelled

from .analysis_helpers import new_case, upload

EVTX = Path(__file__).resolve().parents[2] / "fixtures" / "third_party" / "evtx" / "sysmon.evtx"
AUTH = (
    "".join(
        f"Oct 27 08:{i // 60:02d}:{i % 60:02d} srv01 sshd[{i}]: Failed password for root "
        f"from 203.0.113.7 port {40000 + i} ssh2\n"
        for i in range(300)
    )
).encode()
HINTS = {"timezone_hint": "UTC", "year_hint": 2026}


def _counts(engine: Engine, case_id: str) -> dict[str, int]:
    with engine.connect() as conn:
        return {
            "events": conn.execute(
                select(func.count()).where(events.c.case_id == case_id)
            ).scalar_one(),
            "raw": conn.execute(
                select(func.count())
                .select_from(raw_records.join(events, events.c.event_id == raw_records.c.event_id))
                .where(events.c.case_id == case_id)
            ).scalar_one(),
            "members": conn.execute(
                select(func.count()).select_from(event_group_members)
            ).scalar_one(),
        }


def _record_hashes(engine: Engine, case_id: str) -> list[tuple[str, int, str]]:
    with engine.connect() as conn:
        rows = conn.execute(
            select(events.c.parser_name, events.c.record_index, events.c.record_hash)
            .where(events.c.case_id == case_id)
            .order_by(events.c.parser_name, events.c.record_index)
        ).all()
    return [tuple(r) for r in rows]


def _index_names(engine: Engine) -> set[str]:
    with engine.connect() as conn:
        return set(
            conn.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'events'")
            ).scalars()
        )


def _load(api: TestClient, run_jobs: Callable[[], int], name: str) -> str:
    case_id = new_case(api, name)
    upload(api, case_id, EVTX.read_bytes(), "sysmon.evtx")
    upload(api, case_id, AUTH, "auth.log", **HINTS)
    upload(api, case_id, AUTH, "auth.log.copy", **HINTS)  # duplicate group members
    run_jobs()
    return case_id


def test_large_file_load_matches_normal_load(
    api: TestClient, run_jobs: Callable[[], int], engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    normal = _load(api, run_jobs, "normal")
    expected = _counts(engine, normal)
    assert expected["raw"] > 0 and expected["members"] > 0

    seen_during_load: list[bool] = []
    flush = parse_module._BulkWriter.flush

    def watching(self: Any, batch: list[Any]) -> None:
        with engine.connect() as conn:
            seen_during_load.append(bulk.bulk_load_in_progress(conn))
        flush(self, batch)

    monkeypatch.setattr(parse_module, "DEFER_INDEXES_MIN_BYTES", 0)
    monkeypatch.setattr(parse_module._BulkWriter, "flush", watching)
    deferred = _load(api, run_jobs, "deferred")

    assert seen_during_load and all(seen_during_load)
    assert {str(i.name) for i in bulk.DEFERRED_INDEXES} <= _index_names(engine)
    counts = _counts(engine, deferred)
    assert counts["events"] == expected["events"] and counts["raw"] == expected["raw"]
    assert _record_hashes(engine, deferred) == _record_hashes(engine, normal)
    # Foreign keys are enforced again: deleting the case cascades to raw records.
    response = api.request("DELETE", f"/api/cases/{deferred}", json={"confirm_name": "deferred"})
    assert response.status_code == 200
    assert _counts(engine, deferred) == {"events": 0, "raw": 0, "members": counts["members"] // 2}


def test_cancelled_large_load_restores_indexes(
    api: TestClient, run_jobs: Callable[[], int], engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def cancel(self: Any, batch: list[Any]) -> None:
        raise JobCancelled

    monkeypatch.setattr(parse_module, "DEFER_INDEXES_MIN_BYTES", 0)
    monkeypatch.setattr(parse_module._BulkWriter, "flush", cancel)
    case_id = new_case(api)
    upload(api, case_id, AUTH, "auth.log", **HINTS)
    run_jobs()
    files = api.get(f"/api/cases/{case_id}/files").json()
    assert files[0]["parse"]["status"] == "cancelled"
    assert {str(i.name) for i in bulk.DEFERRED_INDEXES} <= _index_names(engine)
    assert _counts(engine, case_id)["events"] == 0


def test_interrupted_load_is_repaired_at_worker_start(engine: Engine) -> None:
    with engine.begin() as conn:
        bulk.drop_deferred_indexes(conn)
        assert bulk.bulk_load_in_progress(conn)
    bulk.ensure_event_indexes(engine)
    assert {str(i.name) for i in bulk.DEFERRED_INDEXES} <= _index_names(engine)


def test_case_deletion_waits_for_a_bulk_load(api: TestClient, engine: Engine) -> None:
    case_id = new_case(api, "busy")
    with engine.begin() as conn:
        bulk.drop_deferred_indexes(conn)
    refused = api.request("DELETE", f"/api/cases/{case_id}", json={"confirm_name": "busy"})
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "CASE_BUSY"
    bulk.ensure_event_indexes(engine)
    allowed = api.request("DELETE", f"/api/cases/{case_id}", json={"confirm_name": "busy"})
    assert allowed.status_code == 200


def test_migration_keeps_events_and_references(
    api: TestClient, run_jobs: Callable[[], int], engine: Engine
) -> None:
    case_id = _load(api, run_jobs, "migrated")
    before = _counts(engine, case_id)
    hashes = _record_hashes(engine, case_id)
    config = _alembic_config()
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        conn.commit()
        with conn.begin():
            config.attributes["connection"] = conn
            command.downgrade(config, "0006")
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        conn.commit()
        primary = (
            conn.exec_driver_sql("SELECT name FROM pragma_table_info('events') WHERE pk = 1")
            .scalars()
            .all()
        )
    assert primary == ["event_id"]
    assert _counts(engine, case_id) == before

    upgrade_db(engine)
    with engine.connect() as conn:
        primary = (
            conn.exec_driver_sql("SELECT name FROM pragma_table_info('events') WHERE pk = 1")
            .scalars()
            .all()
        )
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    assert primary == []
    assert "ix_events_event_id" in _index_names(engine)
    assert _counts(engine, case_id) == before
    assert _record_hashes(engine, case_id) == hashes
