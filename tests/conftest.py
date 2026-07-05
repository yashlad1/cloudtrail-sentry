"""Shared test fixtures and helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cloudtrail_sentry.engine import Engine
from cloudtrail_sentry.events import CloudTrailEvent
from cloudtrail_sentry.models import Finding, Severity
from cloudtrail_sentry.rules.base import Rule

FIXTURES = Path(__file__).parent / "fixtures"


def _base_record() -> dict[str, Any]:
    return {
        "eventVersion": "1.09",
        "eventTime": "2026-06-30T14:22:31Z",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.47",
        "userAgent": "aws-cli/2.15.0",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE0000000001",
            "arn": "arn:aws:iam::111111111111:user/alice",
            "accountId": "111111111111",
            "userName": "alice",
            "accessKeyId": "AKIAEXAMPLE00000001",
        },
        "requestParameters": {},
        "responseElements": {},
        "readOnly": False,
        "eventType": "AwsApiCall",
        "recipientAccountId": "111111111111",
        "eventID": "e1a2c3d4-0000-0000-0000-000000000001",
    }


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def make_record() -> Callable[..., dict[str, Any]]:
    """Return a factory that builds a CloudTrail record dict with overrides."""

    def _factory(**overrides: Any) -> dict[str, Any]:
        record = _base_record()
        record.update(overrides)
        return record

    return _factory


@pytest.fixture
def make_event(
    make_record: Callable[..., dict[str, Any]],
) -> Callable[..., CloudTrailEvent]:
    """Return a factory that builds a parsed :class:`CloudTrailEvent`."""

    def _factory(**overrides: Any) -> CloudTrailEvent:
        return CloudTrailEvent.from_record(make_record(**overrides))

    return _factory


@pytest.fixture
def run() -> Callable[..., list[Finding]]:
    """Return a helper that runs all rules over one or more records."""

    def _run(
        records: dict[str, Any] | list[dict[str, Any]],
        *,
        rules: list[Rule] | None = None,
        min_severity: Severity = Severity.INFO,
    ) -> list[Finding]:
        if isinstance(records, dict):
            records = [records]
        events = [CloudTrailEvent.from_record(r) for r in records]
        return Engine(rules, min_severity=min_severity).run(events)

    return _run


def load_records(path: Path) -> list[dict[str, Any]]:
    """Load the ``Records`` array from a fixture file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("Records", data) if isinstance(data, dict) else data
    return list(records)
