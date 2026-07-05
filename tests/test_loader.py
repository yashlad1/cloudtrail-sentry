"""Tests for the CloudTrail loader."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from cloudtrail_sentry.loader import LoaderError, iter_events

_REC = {
    "eventName": "StopLogging",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventID": "id-1",
}


def _write(path: Path, obj: object) -> Path:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def test_reads_records_envelope(tmp_path: Path) -> None:
    path = _write(tmp_path / "log.json", {"Records": [_REC]})
    events = list(iter_events([path]))
    assert [e.event_name for e in events] == ["StopLogging"]


def test_reads_bare_array(tmp_path: Path) -> None:
    path = _write(tmp_path / "log.json", [_REC])
    assert len(list(iter_events([path]))) == 1


def test_reads_single_object(tmp_path: Path) -> None:
    path = _write(tmp_path / "log.json", _REC)
    assert len(list(iter_events([path]))) == 1


def test_reads_gzip(tmp_path: Path) -> None:
    path = tmp_path / "log.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump({"Records": [_REC]}, fh)
    assert len(list(iter_events([path]))) == 1


def test_reads_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_text(json.dumps(_REC) + "\n" + json.dumps({**_REC, "eventID": "id-2"}) + "\n")
    assert len(list(iter_events([path]))) == 2


def test_deduplicates_on_event_id(tmp_path: Path) -> None:
    path = _write(tmp_path / "log.json", {"Records": [_REC, dict(_REC)]})
    assert len(list(iter_events([path]))) == 1


def test_directory_recursion(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    _write(tmp_path / "a.json", {"Records": [_REC]})
    _write(tmp_path / "sub" / "b.json", {"Records": [{**_REC, "eventID": "id-2"}]})
    assert len(list(iter_events([tmp_path]))) == 2


def test_malformed_skipped_by_default(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    warnings: list[str] = []
    events = list(iter_events([path], warn=warnings.append))
    assert events == []
    assert warnings and "invalid JSON" in warnings[0]


def test_malformed_raises_when_strict(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(LoaderError):
        list(iter_events([path], strict=True))


def test_missing_records_key_reported(tmp_path: Path) -> None:
    path = _write(tmp_path / "obj.json", {"foo": "bar"})
    warnings: list[str] = []
    assert list(iter_events([path], warn=warnings.append)) == []
    assert warnings and "Records" in warnings[0]


def test_nonexistent_path_reported() -> None:
    warnings: list[str] = []
    assert list(iter_events(["/no/such/file.json"], warn=warnings.append)) == []
    assert warnings and "does not exist" in warnings[0]


def test_empty_directory_reported(tmp_path: Path) -> None:
    warnings: list[str] = []
    assert list(iter_events([tmp_path], warn=warnings.append)) == []
    assert warnings and "no CloudTrail JSON files" in warnings[0]
