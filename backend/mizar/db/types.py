"""Custom column types."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import String
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

from mizar.core.timeutil import from_utc_storage, to_utc_storage


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetime stored as fixed-width ISO 8601 text.

    Naive datetimes raise instead of being silently treated as UTC.
    """

    impl = String(27)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> str | None:
        return None if value is None else to_utc_storage(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        return None if value is None else from_utc_storage(value)
