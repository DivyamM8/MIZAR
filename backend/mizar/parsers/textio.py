"""Framing helpers shared by text-based parsers.

Lines keep their exact original bytes and byte offsets (UTF-8 family). For
UTF-16 files offsets are computed from the decoded text, so they are exact for
valid input. Lines over MAX_LINE_BYTES are capped for parsing and storage; the
locator keeps the full length and the record hash covers the full line.
"""

from __future__ import annotations

import codecs
import hashlib
import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO

MAX_LINE_BYTES = 1024 * 1024
_READ_CHUNK = 1024 * 1024
_UTF16 = ("utf-16-le", "utf-16-be")
_BOMS = {"utf-8-sig": b"\xef\xbb\xbf", "utf-16-le": b"\xff\xfe", "utf-16-be": b"\xfe\xff"}


@dataclass(frozen=True)
class Line:
    number: int  # 1-based
    offset: int  # byte offset of the first byte of the line
    length: int  # full byte length, excluding the line terminator
    raw: bytes  # original bytes, capped at MAX_LINE_BYTES
    text: str
    truncated: bool
    replaced: bool  # undecodable bytes were replaced for display
    full_hash: str | None  # set only when truncated

    def locator(self) -> dict[str, Any]:
        return {
            "kind": "line",
            "line": self.number,
            "byte_offset": self.offset,
            "byte_length": self.length,
        }

    def warnings(self) -> list[str]:
        found = []
        if self.truncated:
            found.append("truncated_record")
        if self.replaced:
            found.append("encoding_replaced")
        return found


def _decode(raw: bytes, encoding: str) -> tuple[str, bool]:
    try:
        return raw.decode(encoding), False
    except UnicodeDecodeError:
        return raw.decode(encoding, errors="replace"), True


def _skip_bom(stream: BinaryIO, encoding: str) -> int:
    bom = _BOMS.get(encoding)
    if bom is None:
        return 0
    head = stream.read(len(bom))
    if head == bom:
        return len(bom)
    stream.seek(0)
    return 0


def iter_lines(stream: BinaryIO, encoding: str | None) -> Iterator[Line]:
    """Yield non-empty lines. Blank lines are skipped (line numbers stay exact)."""
    encoding = encoding or "utf-8"
    if encoding in _UTF16:
        yield from _iter_lines_utf16(stream, encoding)
        return
    text_encoding = "utf-8" if encoding == "utf-8-sig" else encoding
    offset = _skip_bom(stream, encoding)
    number = 0
    while True:
        chunk = stream.readline(MAX_LINE_BYTES + 1)
        if not chunk:
            return
        number += 1
        start = offset
        if len(chunk) > MAX_LINE_BYTES and not chunk.endswith(b"\n"):
            line, consumed = _overlong_line(stream, chunk, number, start, text_encoding)
            offset = start + consumed
            yield line
            continue
        offset += len(chunk)
        raw = chunk[:-1] if chunk.endswith(b"\n") else chunk
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw.strip():
            continue
        text, replaced = _decode(raw, text_encoding)
        yield Line(number, start, len(raw), raw, text, False, replaced, None)


def _overlong_line(
    stream: BinaryIO, first: bytes, number: int, start: int, encoding: str
) -> tuple[Line, int]:
    """Consume the rest of an overlong line; hash all of it, keep the first part."""
    digest = hashlib.sha256(first)
    consumed = len(first)
    terminator = 0
    while True:
        more = stream.readline(_READ_CHUNK)
        if not more:
            break
        consumed += len(more)
        if more.endswith(b"\n"):
            body = more[:-1]
            terminator = 1
            if body.endswith(b"\r"):
                body = body[:-1]
                terminator = 2
            digest.update(body)
            break
        digest.update(more)
    capped = first[:MAX_LINE_BYTES]
    text, replaced = _decode(capped, encoding)
    line = Line(
        number, start, consumed - terminator, capped, text, True, replaced, digest.hexdigest()
    )
    return line, consumed


def _iter_lines_utf16(stream: BinaryIO, encoding: str) -> Iterator[Line]:
    offset = _skip_bom(stream, "utf-16-le" if encoding == "utf-16-le" else "utf-16-be")
    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
    pending = ""
    number = 0
    eof = False
    while not eof:
        block = stream.read(_READ_CHUNK)
        eof = not block
        pending += decoder.decode(block, final=eof)
        parts = pending.split("\n")
        pending = "" if eof else parts.pop()
        for part in parts:
            number += 1
            encoded_len = len((part + "\n").encode(encoding))
            start = offset
            offset += encoded_len
            text = part[:-1] if part.endswith("\r") else part
            if not text.strip():
                continue
            raw = text.encode(encoding)
            truncated = len(raw) > MAX_LINE_BYTES
            full_hash = hashlib.sha256(raw).hexdigest() if truncated else None
            yield Line(
                number,
                start,
                len(raw),
                raw[:MAX_LINE_BYTES],
                text[: MAX_LINE_BYTES // 2],
                truncated,
                "�" in text,
                full_hash,
            )


def decoded_chunks(stream: BinaryIO, encoding: str | None) -> Iterator[str]:
    """The file as decoded text chunks (for formats framed by content, not lines)."""
    encoding = encoding or "utf-8"
    text_encoding = "utf-8" if encoding == "utf-8-sig" else encoding
    _skip_bom(stream, encoding)
    decoder = codecs.getincrementaldecoder(text_encoding)(errors="replace")
    while True:
        block = stream.read(_READ_CHUNK)
        if not block:
            tail = decoder.decode(b"", final=True)
            if tail:
                yield tail
            return
        text = decoder.decode(block)
        if text:
            yield text


class JsonArrayError(Exception):
    pass


MAX_JSON_ITEM_CHARS = 16 * 1024 * 1024


def iter_json_array(chunks: Iterator[str]) -> Iterator[tuple[int, int, str, Any]]:
    """Stream the items of a top-level JSON array: (index, char_offset, text, value)."""
    decoder = json.JSONDecoder()
    buffer = ""
    base = 0  # char offset of buffer[0] in the whole text
    position = 0
    index = 0
    started = False
    exhausted = False

    def refill() -> bool:
        nonlocal buffer, base, position, exhausted
        if exhausted:
            return False
        try:
            more = next(chunks)
        except StopIteration:
            exhausted = True
            return False
        buffer = buffer[position:] + more
        base += position
        position = 0
        return True

    while True:
        while position < len(buffer) and buffer[position] in " \t\r\n,":
            position += 1
        if position >= len(buffer):
            if not refill():
                if not started:
                    raise JsonArrayError("empty input")
                raise JsonArrayError("array not terminated")
            continue
        char = buffer[position]
        if not started:
            if char != "[":
                raise JsonArrayError("not a JSON array")
            started = True
            position += 1
            continue
        if char == "]":
            return
        try:
            value, end = decoder.raw_decode(buffer, position)
        except json.JSONDecodeError as exc:
            if len(buffer) - position > MAX_JSON_ITEM_CHARS:
                raise JsonArrayError(f"array item too large or invalid: {exc.msg}") from exc
            if refill():
                continue
            raise JsonArrayError(f"invalid JSON at item {index}: {exc.msg}") from exc
        if end == len(buffer) and not exhausted and refill():
            # A number or literal may continue in the next chunk; decode again.
            continue
        yield index, base + position, buffer[position:end], value
        index += 1
        position = end
