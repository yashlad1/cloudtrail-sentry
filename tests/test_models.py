"""Tests for the core data models."""

from __future__ import annotations

import pytest

from cloudtrail_sentry.models import ExitCode, Finding, Severity


def test_severity_is_ordered() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL >= Severity.HIGH


def test_severity_str_is_name() -> None:
    assert str(Severity.HIGH) == "HIGH"
    assert f"{Severity.CRITICAL}" == "CRITICAL"


@pytest.mark.parametrize("text", ["high", "HIGH", " High ", "critical"])
def test_severity_parse_case_insensitive(text: str) -> None:
    assert Severity.parse(text) in Severity


def test_severity_parse_invalid_raises() -> None:
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("bogus")


def test_exit_codes() -> None:
    assert int(ExitCode.OK) == 0
    assert int(ExitCode.FINDINGS) == 1
    assert int(ExitCode.USAGE) == 2
    assert int(ExitCode.RUNTIME) == 3


def test_finding_to_dict_serializes_severity_name() -> None:
    finding = Finding(
        rule="EXAMPLE",
        severity=Severity.HIGH,
        resource="res-1",
        remediation="fix it",
        description="something",
    )
    data = finding.to_dict()
    assert data["severity"] == "HIGH"
    assert data["rule"] == "EXAMPLE"
    assert data["resource"] == "res-1"
    assert data["remediation"] == "fix it"
    # Optional context fields are present (as None when unset).
    assert data["account_id"] is None


def test_finding_is_frozen() -> None:
    finding = Finding(rule="R", severity=Severity.LOW, resource="x", remediation="y")
    with pytest.raises(AttributeError):
        finding.rule = "other"  # type: ignore[misc]
