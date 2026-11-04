"""The fallback font for PDF reports (DESIGN.md D40)."""

from __future__ import annotations

from functools import cache
from pathlib import Path

FONT_DIR = Path(__file__).parent
FALLBACK_FONT = "MizarFallback"
FALLBACK_FILE = FONT_DIR / "DejaVuSans.ttf"


@cache
def fallback_code_points() -> frozenset[int]:
    """Code points the fallback font has glyphs for; registers it with ReportLab once."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font = TTFont(FALLBACK_FONT, str(FALLBACK_FILE))
    pdfmetrics.registerFont(font)
    return frozenset(font.face.charToGlyph)
