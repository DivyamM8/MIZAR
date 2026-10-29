"""FastAPI dependencies for shared application state."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import Engine

from mizar.core.config import Settings
from mizar.evidence.store import EvidenceStore


def _engine(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _store(request: Request) -> EvidenceStore:
    store: EvidenceStore = request.app.state.store
    return store


EngineDep = Annotated[Engine, Depends(_engine)]
SettingsDep = Annotated[Settings, Depends(_settings)]
StoreDep = Annotated[EvidenceStore, Depends(_store)]
