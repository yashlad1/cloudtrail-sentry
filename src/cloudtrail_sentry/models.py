"""Core data models: severity levels, findings, and process exit codes.

These are deliberately built on the standard library (``enum`` + ``dataclass``)
rather than a validation framework. CloudTrail's high-value fields are free-form
nested dicts that a strict schema would fight rather than help, so the tool stays
dependency-light and the models stay trivial to serialize and test.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity levels.

    Backed by ``IntEnum`` so findings sort naturally and threshold checks
    (``--min-severity`` / ``--fail-on``) are plain ``>=`` comparisons.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # renders as "HIGH", not "Severity.HIGH"
        return self.name

    @classmethod
    def parse(cls, name: str) -> Severity:
        """Parse a case-insensitive level name (e.g. ``"high"`` -> ``HIGH``)."""
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:  # pragma: no cover - exercised via CLI validation
            valid = ", ".join(level.name for level in cls)
            raise ValueError(f"unknown severity {name!r}; choose one of: {valid}") from exc


class ExitCode(enum.IntEnum):
    """Process exit codes, designed for use as a CI/CD pipeline gate."""

    OK = 0  # ran clean; nothing at/above the --fail-on threshold
    FINDINGS = 1  # findings at/above --fail-on threshold (the build should fail)
    USAGE = 2  # bad CLI arguments (Typer/click convention)
    RUNTIME = 3  # no input found, or malformed input while --strict


@dataclass(frozen=True, slots=True)
class Finding:
    """A single detected issue.

    The first four fields (``rule``, ``severity``, ``resource``,
    ``remediation``) are the contract every finding must satisfy. The remaining
    fields are optional triage context extracted from the source event.
    """

    rule: str
    severity: Severity
    resource: str
    remediation: str
    title: str = ""
    description: str = ""
    account_id: str | None = None
    region: str | None = None
    event_name: str | None = None
    event_time: str | None = None
    source_ip: str | None = None
    actor: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-ready dict with severity as its name string."""
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
