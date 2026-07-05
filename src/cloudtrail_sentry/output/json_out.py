"""JSON output: a metadata envelope around the findings list."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from ..models import Finding, Severity

TOOL_NAME = "cloudtrail-sentry"


def severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    """Count findings per severity, ordered from most to least severe."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.name] = counts.get(finding.severity.name, 0) + 1
    return {
        level.name: counts[level.name]
        for level in sorted(Severity, reverse=True)
        if level.name in counts
    }


def build_report(
    findings: Sequence[Finding], *, events_scanned: int, version: str
) -> dict[str, Any]:
    """Assemble the full JSON report structure."""
    return {
        "tool": TOOL_NAME,
        "version": version,
        "summary": {
            "events_scanned": events_scanned,
            "findings": len(findings),
            "by_severity": severity_counts(findings),
        },
        "findings": [finding.to_dict() for finding in findings],
    }


def render_json(
    findings: Sequence[Finding], *, events_scanned: int, version: str, indent: int = 2
) -> str:
    """Render findings as an indented JSON string (no trailing newline)."""
    report = build_report(findings, events_scanned=events_scanned, version=version)
    return json.dumps(report, indent=indent, sort_keys=False)
