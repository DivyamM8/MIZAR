"""Analysis runs, findings and the rule catalogue."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, status

from mizar.api.deps import EngineDep
from mizar.api.schemas import (
    FindingDetail,
    FindingSummary,
    FindingUpdate,
    RuleOut,
    RunCreate,
    RunDetail,
    RunOut,
    RunStarted,
)
from mizar.detection import service
from mizar.detection.rules import load_rules
from mizar.detection.runs import start_run

router = APIRouter(tags=["analysis"])


@router.get("/api/rules")
def list_rules() -> list[RuleOut]:
    return [RuleOut(**rule.catalogue_entry()) for rule in load_rules()]


@router.post("/api/cases/{case_id}/runs", status_code=status.HTTP_202_ACCEPTED)
def create_run(case_id: str, body: RunCreate, engine: EngineDep) -> RunStarted:
    return RunStarted(**start_run(engine, case_id, body.overrides))


@router.get("/api/cases/{case_id}/runs")
def list_runs(case_id: str, engine: EngineDep) -> list[RunOut]:
    return [RunOut(**row) for row in service.list_runs(engine, case_id)]


@router.get("/api/runs/{run_id}")
def get_run(run_id: str, engine: EngineDep) -> RunDetail:
    return RunDetail(**service.get_run(engine, run_id))


@router.get("/api/runs/{run_id}/findings")
def list_findings(
    run_id: str,
    engine: EngineDep,
    severity: str | None = None,
    finding_status: Annotated[str | None, Query(alias="status")] = None,
    rule_id: str | None = None,
) -> list[FindingSummary]:
    """Findings in priority order: severity, confidence, evidence strength, time."""
    rows = service.list_findings(
        engine, run_id, severity=severity, status=finding_status, rule_id=rule_id
    )
    return [FindingSummary(**row) for row in rows]


@router.get("/api/findings/{finding_id}")
def get_finding(
    finding_id: str, engine: EngineDep, offset: Annotated[int, Query(ge=0)] = 0
) -> FindingDetail:
    return FindingDetail(**service.get_finding(engine, finding_id, offset))


@router.patch("/api/findings/{finding_id}")
def update_finding(finding_id: str, body: FindingUpdate, engine: EngineDep) -> FindingDetail:
    changes = body.model_dump(exclude_unset=True)
    return FindingDetail(**service.update_finding(engine, finding_id, changes))
