"""The :class:`Rule` base class every detection rule extends.

A rule is a small class that declares its identity (``id``, ``title``,
``severity``, ``remediation``) and which ``eventName`` values it cares about,
then implements :meth:`Rule.evaluate` to yield findings for a single event.
Rules that need to reason across the whole log (rate/burst detection) buffer
state in ``evaluate`` and emit from :meth:`Rule.finalize`.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from typing import ClassVar

from ..events import CloudTrailEvent
from ..models import Finding, Severity


class Rule(abc.ABC):
    """Abstract base for all detection rules.

    Subclasses set the class-level metadata and implement :meth:`evaluate`.
    Instances are created fresh per scan (see
    :func:`cloudtrail_sentry.registry.all_rules`), so stateful correlation rules
    may safely accumulate on ``self``.
    """

    #: Stable machine identifier, SCREAMING_SNAKE_CASE (e.g. ``"ROOT_ACCOUNT_USED"``).
    id: ClassVar[str]
    #: Human-readable one-line title.
    title: ClassVar[str]
    #: Default severity for findings this rule emits.
    severity: ClassVar[Severity]
    #: Default remediation guidance.
    remediation: ClassVar[str]
    #: One-line explanation of what the rule detects (used by ``cts rules``).
    description: ClassVar[str] = ""
    #: ``eventName`` values this rule applies to. Empty means "inspect every event".
    event_names: ClassVar[frozenset[str]] = frozenset()

    def matches(self, event: CloudTrailEvent) -> bool:
        """Cheap pre-filter so :meth:`evaluate` only runs on relevant events."""
        return not self.event_names or event.event_name in self.event_names

    @abc.abstractmethod
    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        """Yield zero or more findings for a single event."""
        raise NotImplementedError

    def finalize(self) -> Iterable[Finding]:
        """Emit findings after the whole event stream (for correlation rules)."""
        return ()

    def finding(
        self,
        resource: str,
        *,
        event: CloudTrailEvent | None = None,
        severity: Severity | None = None,
        title: str | None = None,
        description: str = "",
        remediation: str | None = None,
    ) -> Finding:
        """Construct a :class:`Finding`, defaulting to this rule's metadata and
        pulling triage context (account, region, actor, timestamp) from ``event``.
        """
        return Finding(
            rule=self.id,
            severity=severity if severity is not None else self.severity,
            resource=resource,
            remediation=remediation if remediation is not None else self.remediation,
            title=title if title is not None else self.title,
            description=description,
            account_id=event.account_id if event else None,
            region=event.region if event else None,
            event_name=event.event_name if event else None,
            event_time=event.event_time if event else None,
            source_ip=event.source_ip if event else None,
            actor=event.actor_arn if event else None,
        )
