"""The detection engine: stream events through rules, collect findings."""

from __future__ import annotations

from collections.abc import Iterable

from .events import CloudTrailEvent
from .models import Finding, Severity
from .registry import all_rules
from .rules.base import Rule


class Engine:
    """Runs a set of rules over a stream of events and returns sorted findings."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        min_severity: Severity = Severity.INFO,
    ) -> None:
        self.rules = rules if rules is not None else all_rules()
        self.min_severity = min_severity
        self.events_scanned = 0

    def run(self, events: Iterable[CloudTrailEvent]) -> list[Finding]:
        """Evaluate every rule against each event, then run correlation hooks.

        Events are consumed lazily so a large log streams through rather than
        being materialized in memory. Findings below ``min_severity`` are
        dropped and the rest are sorted by severity (desc), then rule id and
        resource for stable, deterministic output.
        """
        self.events_scanned = 0
        findings: list[Finding] = []
        for event in events:
            self.events_scanned += 1
            for rule in self.rules:
                if rule.matches(event):
                    findings.extend(rule.evaluate(event))
        for rule in self.rules:
            findings.extend(rule.finalize())

        findings = [f for f in findings if f.severity >= self.min_severity]
        findings.sort(key=lambda f: (-f.severity, f.rule, f.resource))
        return findings
