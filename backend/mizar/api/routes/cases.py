"""Case endpoints."""

from __future__ import annotations

from fastapi import APIRouter, status

from mizar.api.deps import EngineDep, SettingsDep, StoreDep
from mizar.api.schemas import CaseCreate, CaseDelete, CaseDeleted, CaseOut, CaseUpdate
from mizar.cases import service

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_case(body: CaseCreate, engine: EngineDep) -> CaseOut:
    return CaseOut(**service.create_case(engine, body.model_dump()))


@router.get("")
def list_cases(engine: EngineDep) -> list[CaseOut]:
    return [CaseOut(**row) for row in service.list_cases(engine)]


@router.get("/{case_id}")
def get_case(case_id: str, engine: EngineDep) -> CaseOut:
    return CaseOut(**service.get_case(engine, case_id))


@router.patch("/{case_id}")
def update_case(case_id: str, body: CaseUpdate, engine: EngineDep) -> CaseOut:
    return CaseOut(**service.update_case(engine, case_id, body.model_dump(exclude_unset=True)))


@router.delete("/{case_id}")
def delete_case(
    case_id: str, body: CaseDelete, engine: EngineDep, store: StoreDep, settings: SettingsDep
) -> CaseDeleted:
    return CaseDeleted(
        **service.delete_case(engine, store, settings.exports_dir, case_id, body.confirm_name)
    )
