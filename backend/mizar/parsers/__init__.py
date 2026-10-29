"""Parsers for the v1 formats. Importing this package registers all of them."""

from mizar.parsers import auditd, generic, network, syslog, windows  # noqa: F401
from mizar.parsers.base import REGISTRY

__all__ = ["REGISTRY"]
