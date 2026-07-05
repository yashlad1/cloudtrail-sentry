"""Load CloudTrail records from local files and directories into events.

Supports the canonical S3-delivery envelope ``{"Records": [...]}``, a bare
array of records, a single record object, gzip (``.json.gz``), and
newline-delimited JSON (``.jsonl`` / ``.ndjson``). Directories are searched
recursively. Records are de-duplicated on ``eventID``.

Malformed input is skipped (with an optional warning) by default, or raised as
:class:`LoaderError` when ``strict=True`` — this is what lets ``cts scan
--strict`` fail a CI pipeline on bad input.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

from .events import CloudTrailEvent

WarnFn = Callable[[str], None]

_JSON_GLOBS = ("*.json", "*.json.gz", "*.jsonl", "*.jsonl.gz", "*.ndjson")


class LoaderError(RuntimeError):
    """Raised for missing or malformed input when running in strict mode."""


def _report(message: str, *, strict: bool, warn: WarnFn | None) -> None:
    if strict:
        raise LoaderError(message)
    if warn is not None:
        warn(message)


def _read_text(path: Path) -> str:
    if path.name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return fh.read()
    return path.read_text(encoding="utf-8")


def _iter_files(
    paths: Iterable[str | Path], *, strict: bool, warn: WarnFn | None
) -> Iterator[Path]:
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found = sorted({match for glob in _JSON_GLOBS for match in path.rglob(glob)})
            if not found:
                _report(f"no CloudTrail JSON files found under {path}", strict=strict, warn=warn)
            yield from found
        elif path.is_file():
            yield path
        else:
            _report(f"path does not exist: {path}", strict=strict, warn=warn)


def _extract_records(
    obj: Any, *, path: Path, strict: bool, warn: WarnFn | None
) -> Iterator[dict[str, Any]]:
    if isinstance(obj, dict):
        records = obj.get("Records")
        if isinstance(records, list):
            for rec in records:
                if isinstance(rec, dict):
                    yield rec
            return
        if "eventName" in obj or "eventSource" in obj:
            yield obj
            return
        _report(f"{path}: JSON object has no 'Records' array", strict=strict, warn=warn)
        return
    if isinstance(obj, list):
        for rec in obj:
            if isinstance(rec, dict):
                yield rec
        return
    _report(
        f"{path}: unexpected top-level JSON type {type(obj).__name__}",
        strict=strict,
        warn=warn,
    )


def _records_from_path(
    path: Path, *, strict: bool, warn: WarnFn | None
) -> Iterator[dict[str, Any]]:
    try:
        text = _read_text(path)
    except (OSError, EOFError) as exc:
        _report(f"could not read {path}: {exc}", strict=strict, warn=warn)
        return

    stem = path.name[:-3] if path.name.endswith(".gz") else path.name
    if stem.endswith((".jsonl", ".ndjson")):
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except ValueError as exc:
                _report(f"{path}:{lineno}: invalid JSON: {exc}", strict=strict, warn=warn)
                continue
            yield from _extract_records(obj, path=path, strict=strict, warn=warn)
        return

    try:
        obj = json.loads(text)
    except ValueError as exc:
        _report(f"{path}: invalid JSON: {exc}", strict=strict, warn=warn)
        return
    yield from _extract_records(obj, path=path, strict=strict, warn=warn)


def iter_events(
    paths: Iterable[str | Path],
    *,
    strict: bool = False,
    warn: WarnFn | None = None,
) -> Iterator[CloudTrailEvent]:
    """Yield :class:`CloudTrailEvent` objects from the given files/directories.

    Events are streamed lazily and de-duplicated on ``eventID`` so a large log
    never has to be held in memory at once.
    """
    seen: set[str] = set()
    for path in _iter_files(paths, strict=strict, warn=warn):
        for rec in _records_from_path(path, strict=strict, warn=warn):
            eid = rec.get("eventID")
            if isinstance(eid, str) and eid:
                if eid in seen:
                    continue
                seen.add(eid)
            yield CloudTrailEvent.from_record(rec)
