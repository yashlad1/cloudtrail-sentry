"""Tests for the detection engine (ordering, filtering, correlation)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cloudtrail_sentry.engine import Engine
from cloudtrail_sentry.events import CloudTrailEvent
from cloudtrail_sentry.models import Finding, Severity

_NOISY_INCIDENT_RULES = {
    "ROOT_ACCOUNT_USED",
    "CONSOLE_LOGIN_WITHOUT_MFA",
    "IAM_USER_CREATED",
    "IAM_ACCESS_KEY_CREATED",
    "IAM_ADMIN_POLICY_ATTACHED",
    "SECURITY_GROUP_OPEN_TO_INTERNET",
    "S3_BUCKET_EXPOSED_PUBLIC",
    "CLOUDTRAIL_LOGGING_DISABLED",
    "GUARDDUTY_DISABLED",
}


def _events(path: Path) -> list[CloudTrailEvent]:
    records = json.loads(path.read_text(encoding="utf-8"))["Records"]
    return [CloudTrailEvent.from_record(r) for r in records]


def test_noisy_incident_fires_expected_rules(fixtures_dir: Path) -> None:
    findings = Engine().run(_events(fixtures_dir / "noisy_incident.json"))
    assert {f.rule for f in findings} == _NOISY_INCIDENT_RULES


def test_clean_baseline_has_no_findings(fixtures_dir: Path) -> None:
    assert Engine().run(_events(fixtures_dir / "clean_baseline.json")) == []


def test_findings_sorted_by_severity_desc(fixtures_dir: Path) -> None:
    findings = Engine().run(_events(fixtures_dir / "noisy_incident.json"))
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, reverse=True)


def test_min_severity_filters_lower_findings(fixtures_dir: Path) -> None:
    findings = Engine(min_severity=Severity.HIGH).run(_events(fixtures_dir / "noisy_incident.json"))
    assert all(f.severity >= Severity.HIGH for f in findings)
    assert "IAM_USER_CREATED" not in {f.rule for f in findings}  # it is MEDIUM


def test_events_scanned_counts_every_record(fixtures_dir: Path) -> None:
    engine = Engine()
    engine.run(_events(fixtures_dir / "noisy_incident.json"))
    assert engine.events_scanned == 8


def test_events_scanned_resets_between_runs(fixtures_dir: Path) -> None:
    engine = Engine()
    events = _events(fixtures_dir / "noisy_incident.json")
    engine.run(events)
    engine.run(events)
    assert engine.events_scanned == 8


def _console_login(
    make_record: Callable[..., dict[str, Any]], result: str, ip: str
) -> dict[str, Any]:
    return make_record(
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        responseElements={"ConsoleLogin": result},
        additionalEventData={"MFAUsed": "No"},
        sourceIPAddress=ip,
        userIdentity={"type": "IAMUser", "userName": "bob", "accountId": "111111111111"},
    )


def _run(records: list[dict[str, Any]]) -> list[Finding]:
    return Engine().run([CloudTrailEvent.from_record(r) for r in records])


def test_brute_force_below_threshold_is_silent(make_record: Callable[..., dict[str, Any]]) -> None:
    records = [_console_login(make_record, "Failure", "198.51.100.9") for _ in range(4)]
    assert not [f for f in _run(records) if f.rule == "CONSOLE_LOGIN_BRUTE_FORCE"]


def test_brute_force_at_threshold_fires(make_record: Callable[..., dict[str, Any]]) -> None:
    records = [_console_login(make_record, "Failure", "198.51.100.9") for _ in range(5)]
    hits = [f for f in _run(records) if f.rule == "CONSOLE_LOGIN_BRUTE_FORCE"]
    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH


def test_brute_force_with_success_escalates(make_record: Callable[..., dict[str, Any]]) -> None:
    records = [_console_login(make_record, "Failure", "198.51.100.9") for _ in range(5)]
    records.append(_console_login(make_record, "Success", "198.51.100.9"))
    hits = [f for f in _run(records) if f.rule == "CONSOLE_LOGIN_BRUTE_FORCE"]
    assert hits and hits[0].severity == Severity.CRITICAL
