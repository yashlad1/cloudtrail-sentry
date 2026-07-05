"""Tests for the logging / threat-detection tampering rules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cloudtrail_sentry.models import Finding, Severity

Record = Callable[..., dict[str, Any]]
Run = Callable[..., list[Finding]]


def _hits(findings: list[Finding], rule: str) -> list[Finding]:
    return [f for f in findings if f.rule == rule]


def _ev(
    make_record: Record, source: str, name: str, params: dict[str, Any], **over: Any
) -> dict[str, Any]:
    return make_record(eventName=name, eventSource=source, requestParameters=params, **over)


def test_stop_logging_is_critical(make_record: Record, run: Run) -> None:
    rec = _ev(make_record, "cloudtrail.amazonaws.com", "StopLogging", {"name": "t"})
    hits = _hits(run(rec), "CLOUDTRAIL_LOGGING_DISABLED")
    assert hits and hits[0].severity == Severity.CRITICAL


def test_delete_trail_is_critical(make_record: Record, run: Run) -> None:
    rec = _ev(make_record, "cloudtrail.amazonaws.com", "DeleteTrail", {"name": "t"})
    assert _hits(run(rec), "CLOUDTRAIL_LOGGING_DISABLED")[0].severity == Severity.CRITICAL


def test_update_trail_narrowing_is_high(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "cloudtrail.amazonaws.com",
        "UpdateTrail",
        {"name": "t", "isMultiRegionTrail": False},
    )
    assert _hits(run(rec), "CLOUDTRAIL_LOGGING_DISABLED")[0].severity == Severity.HIGH


def test_update_trail_benign_is_not_flagged(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "cloudtrail.amazonaws.com",
        "UpdateTrail",
        {"name": "t", "isMultiRegionTrail": True, "includeGlobalServiceEvents": True},
    )
    assert not _hits(run(rec), "CLOUDTRAIL_LOGGING_DISABLED")


def test_put_event_selectors_excluding_management_is_high(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "cloudtrail.amazonaws.com",
        "PutEventSelectors",
        {"name": "t", "eventSelectors": [{"includeManagementEvents": False}]},
    )
    assert _hits(run(rec), "CLOUDTRAIL_LOGGING_DISABLED")[0].severity == Severity.HIGH


def test_delete_detector_is_critical(make_record: Record, run: Run) -> None:
    rec = _ev(make_record, "guardduty.amazonaws.com", "DeleteDetector", {"detectorId": "d"})
    assert _hits(run(rec), "GUARDDUTY_DISABLED")[0].severity == Severity.CRITICAL


def test_update_detector_disable_is_critical(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "guardduty.amazonaws.com",
        "UpdateDetector",
        {"detectorId": "d", "enable": False},
    )
    assert _hits(run(rec), "GUARDDUTY_DISABLED")[0].severity == Severity.CRITICAL


def test_update_detector_enable_is_not_flagged(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "guardduty.amazonaws.com",
        "UpdateDetector",
        {"detectorId": "d", "enable": True},
    )
    assert not _hits(run(rec), "GUARDDUTY_DISABLED")


def test_stop_config_recorder_is_high(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "config.amazonaws.com",
        "StopConfigurationRecorder",
        {"configurationRecorderName": "default"},
    )
    assert _hits(run(rec), "AWS_CONFIG_DISABLED")[0].severity == Severity.HIGH


def test_schedule_key_deletion_is_critical(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "kms.amazonaws.com",
        "ScheduleKeyDeletion",
        {"keyId": "k", "pendingWindowInDays": 7},
    )
    assert (
        _hits(run(rec), "KMS_KEY_DISABLED_OR_SCHEDULED_DELETION")[0].severity == Severity.CRITICAL
    )


def test_disable_key_is_high(make_record: Record, run: Run) -> None:
    rec = _ev(make_record, "kms.amazonaws.com", "DisableKey", {"keyId": "k"})
    assert _hits(run(rec), "KMS_KEY_DISABLED_OR_SCHEDULED_DELETION")[0].severity == Severity.HIGH


def test_failed_stop_logging_is_not_flagged(make_record: Record, run: Run) -> None:
    rec = _ev(
        make_record,
        "cloudtrail.amazonaws.com",
        "StopLogging",
        {"name": "t"},
        errorCode="AccessDenied",
    )
    assert not _hits(run(rec), "CLOUDTRAIL_LOGGING_DISABLED")
