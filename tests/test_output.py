"""Tests for JSON and table output rendering (including a golden JSON test)."""

from __future__ import annotations

import json
from pathlib import Path

from cloudtrail_sentry import __version__
from cloudtrail_sentry.engine import Engine
from cloudtrail_sentry.events import CloudTrailEvent
from cloudtrail_sentry.loader import iter_events
from cloudtrail_sentry.models import Finding, Severity
from cloudtrail_sentry.output import (
    build_report,
    render_json,
    render_table_str,
    severity_counts,
)


def _example_findings(fixtures_dir: Path) -> tuple[list[Finding], int]:
    example = fixtures_dir.parent.parent / "examples" / "sample_cloudtrail.json"
    engine = Engine()
    findings = engine.run(iter_events([str(example)]))
    return findings, engine.events_scanned


def test_golden_json_matches(fixtures_dir: Path) -> None:
    findings, scanned = _example_findings(fixtures_dir)
    report = build_report(findings, events_scanned=scanned, version=__version__)
    golden = json.loads((fixtures_dir / "golden" / "sample_findings.json").read_text())
    # Compare the meaningful payload exactly; tolerate version drift.
    assert report["summary"] == golden["summary"]
    assert report["findings"] == golden["findings"]
    assert report["version"] == __version__


def test_render_json_is_valid_json(fixtures_dir: Path) -> None:
    findings, scanned = _example_findings(fixtures_dir)
    parsed = json.loads(render_json(findings, events_scanned=scanned, version=__version__))
    assert parsed["tool"] == "cloudtrail-sentry"
    assert parsed["summary"]["findings"] == len(findings)


def test_severity_counts_ordered_desc() -> None:
    findings = [
        Finding(rule="A", severity=Severity.LOW, resource="r", remediation="x"),
        Finding(rule="B", severity=Severity.CRITICAL, resource="r", remediation="x"),
        Finding(rule="C", severity=Severity.CRITICAL, resource="r", remediation="x"),
    ]
    counts = severity_counts(findings)
    assert list(counts.items()) == [("CRITICAL", 2), ("LOW", 1)]


def test_table_reports_no_findings() -> None:
    out = render_table_str([], events_scanned=5)
    assert "no findings" in out.lower()
    assert "5" in out


def test_table_lists_findings_and_remediation() -> None:
    finding = Finding(
        rule="SECURITY_GROUP_OPEN_TO_INTERNET",
        severity=Severity.HIGH,
        resource="sg-0abcd1234efgh5678",
        remediation="Restrict to a trusted CIDR.",
        description="SSH (22) exposed to 0.0.0.0/0.",
    )
    out = render_table_str([finding], events_scanned=1)
    assert "SECURITY_GROUP_OPEN_TO_INTERNET" in out
    assert "HIGH" in out
    assert "sg-0abcd1234efgh5678" in out
    assert "Fix:" in out


def test_table_orders_critical_before_high(fixtures_dir: Path) -> None:
    records = json.loads((fixtures_dir / "noisy_incident.json").read_text())["Records"]
    findings = Engine().run([CloudTrailEvent.from_record(r) for r in records])
    out = render_table_str(findings, events_scanned=len(records))
    assert out.index("CRITICAL") < out.index("MEDIUM")
