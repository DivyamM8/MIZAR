"""Report and data exports of an analysis run (DESIGN.md §13)."""

from __future__ import annotations

from fastapi import APIRouter, status
from fastapi.responses import FileResponse

from mizar.api.deps import EngineDep, SettingsDep
from mizar.api.schemas import ExportCreate, ExportDeleted, ExportOut, ExportStarted
from mizar.reporting import service

router = APIRouter(tags=["exports"])


@router.post("/api/runs/{run_id}/exports", status_code=status.HTTP_202_ACCEPTED)
def create_export(run_id: str, body: ExportCreate, engine: EngineDep) -> ExportStarted:
    options = body.model_dump(exclude={"format"})
    return ExportStarted(**service.start_export(engine, run_id, body.format, options))


@router.get("/api/runs/{run_id}/exports")
def list_exports(run_id: str, engine: EngineDep, settings: SettingsDep) -> list[ExportOut]:
    rows = service.list_exports(engine, settings.exports_dir, run_id)
    return [ExportOut(**row) for row in rows]


@router.get("/api/exports/{export_id}")
def get_export(export_id: str, engine: EngineDep, settings: SettingsDep) -> ExportOut:
    return ExportOut(**service.get_export(engine, settings.exports_dir, export_id))


@router.get("/api/exports/{export_id}/download", response_class=FileResponse)
def download_export(export_id: str, engine: EngineDep, settings: SettingsDep) -> FileResponse:
    path, media_type, filename = service.download(engine, settings.exports_dir, export_id)
    return FileResponse(path, media_type=media_type, filename=filename)


@router.delete("/api/exports/{export_id}")
def delete_export(export_id: str, engine: EngineDep, settings: SettingsDep) -> ExportDeleted:
    return ExportDeleted(**service.delete_export(engine, settings.exports_dir, export_id))
