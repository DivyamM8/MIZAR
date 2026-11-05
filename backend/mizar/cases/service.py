"""Case lifecycle, including complete deletion (DESIGN.md D15)."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, delete, func, insert, select, update

from mizar.core.errors import ErrorCode, MizarError
from mizar.core.ids import new_case_id
from mizar.core.timeutil import utc_now
from mizar.db.bulk import bulk_load_in_progress
from mizar.db.tables import cases, jobs, source_files
from mizar.evidence.service import release_blob_if_unreferenced, require_case
from mizar.evidence.store import EvidenceStore

log = logging.getLogger(__name__)

_EDITABLE = ("name", "reference", "analyst_name", "description", "default_timezone_hint")


def _with_counts(engine: Engine, case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not case_rows:
        return []
    ids = [row["case_id"] for row in case_rows]
    with engine.connect() as conn:
        counts: dict[str, int] = dict(
            conn.execute(
                select(source_files.c.case_id, func.count())
                .where(source_files.c.case_id.in_(ids))
                .group_by(source_files.c.case_id)
            ).all()
        )
    return [{**row, "file_count": counts.get(row["case_id"], 0)} for row in case_rows]


def create_case(engine: Engine, values: dict[str, Any]) -> dict[str, Any]:
    now = utc_now()
    case_id = new_case_id()
    with engine.begin() as conn:
        conn.execute(
            insert(cases).values(
                case_id=case_id,
                **{key: values.get(key) for key in _EDITABLE},
                created_at=now,
                updated_at=now,
            )
        )
    return get_case(engine, case_id)


def get_case(engine: Engine, case_id: str) -> dict[str, Any]:
    with engine.connect() as conn:
        row = require_case(conn, case_id)
    return _with_counts(engine, [row])[0]


def list_cases(engine: Engine) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        rows = [
            dict(r)
            for r in conn.execute(select(cases).order_by(cases.c.created_at.desc())).mappings()
        ]
    return _with_counts(engine, rows)


def update_case(engine: Engine, case_id: str, changes: dict[str, Any]) -> dict[str, Any]:
    values = {key: changes[key] for key in _EDITABLE if key in changes}
    with engine.begin() as conn:
        require_case(conn, case_id)
        if values:
            conn.execute(
                update(cases)
                .where(cases.c.case_id == case_id)
                .values(**values, updated_at=utc_now())
            )
    return get_case(engine, case_id)


def delete_case(
    engine: Engine, store: EvidenceStore, exports_dir: Path, case_id: str, confirm_name: str
) -> dict[str, Any]:
    """Delete the case, its records, exports and evidence blobs.

    Blobs whose content is also part of another case are kept for that case.
    Refused while a job for the case is running.
    """
    with engine.begin() as conn:
        # Take the write lock first, so no job can be claimed between the check and delete.
        claimed = conn.execute(
            update(cases).where(cases.c.case_id == case_id).values(updated_at=utc_now())
        )
        if claimed.rowcount == 0:
            raise MizarError(
                ErrorCode.CASE_NOT_FOUND, "Case not found.", details={"case_id": case_id}
            )
        case = require_case(conn, case_id)
        if confirm_name != case["name"]:
            raise MizarError(
                ErrorCode.CASE_NAME_MISMATCH,
                "The confirmation does not match the case name exactly.",
            )
        if bulk_load_in_progress(conn):
            raise MizarError(
                ErrorCode.CASE_BUSY,
                "A large file is being loaded. Delete the case when it has finished.",
            )
        running = conn.execute(
            select(func.count()).where(jobs.c.case_id == case_id, jobs.c.status == "running")
        ).scalar_one()
        if running:
            raise MizarError(
                ErrorCode.CASE_BUSY,
                "A job for this case is running. Cancel it or wait for it to finish.",
                details={"running_jobs": running},
            )
        blob_hashes = set(
            conn.execute(
                select(source_files.c.blob_sha256).where(source_files.c.case_id == case_id)
            ).scalars()
        )
        file_count = conn.execute(
            select(func.count()).where(source_files.c.case_id == case_id)
        ).scalar_one()
        # Foreign keys cascade to jobs and source files.
        conn.execute(delete(cases).where(cases.c.case_id == case_id))

    deleted = retained = 0
    errors: list[dict[str, Any]] = []
    for sha256 in sorted(blob_hashes):
        try:
            if release_blob_if_unreferenced(engine, store, sha256):
                deleted += 1
            else:
                retained += 1
        except OSError as exc:
            log.error("could not delete evidence blob %s", sha256, extra={"case_id": case_id})
            errors.append({"sha256": sha256, "error": type(exc).__name__})

    case_exports = exports_dir / case_id
    if case_exports.exists():
        shutil.rmtree(case_exports)

    log.info(
        "case deleted: %d file record(s), %d blob(s) removed, %d shared blob(s) kept",
        file_count,
        deleted,
        retained,
        extra={"case_id": case_id},
    )
    return {
        "case_id": case_id,
        "deleted": True,
        "source_files_deleted": file_count,
        "blobs_deleted": deleted,
        "blobs_retained_shared": retained,
        "blob_errors": errors,
    }
