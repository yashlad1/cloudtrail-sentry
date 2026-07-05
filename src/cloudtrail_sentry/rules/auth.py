"""Authentication and access-anomaly rules (root use, MFA, brute force, recon).

The last two rules are *correlation* rules: they buffer per-event state in
:meth:`evaluate` and emit aggregated findings from :meth:`finalize` once the
whole log has been seen.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from .._util import dig
from ..events import CloudTrailEvent
from ..models import Finding, Severity
from ..registry import register
from .base import Rule

_SIGNIN_SOURCE = "signin.amazonaws.com"
_FEDERATED_TYPES = {"SAMLUser", "WebIdentityUser", "AssumedRole", "FederatedUser"}


@register
class RootAccountUsed(Rule):
    id = "ROOT_ACCOUNT_USED"
    title = "Root account used"
    severity = Severity.CRITICAL
    description = "Root user activity; root should be reserved for break-glass use only."
    remediation = (
        "Stop using root for day-to-day operations. Enable MFA on root, delete any root access "
        "keys, and operate through least-privilege IAM roles."
    )
    # Empty event_names -> inspect every event.

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if not event.is_root or event.is_service_principal:
            return
        resource = event.actor_arn or "root-account"
        access_key = event.access_key_id or ""

        if access_key.startswith("AKIA"):
            severity = Severity.CRITICAL
            description = f"Root account used a long-lived access key ({event.event_name})."
        elif event.event_name == "ConsoleLogin":
            severity = Severity.HIGH
            description = "Root account signed in to the console."
        elif event.is_read_only:
            severity = Severity.MEDIUM
            description = f"Root account performed a read-only action ({event.event_name})."
        elif event.succeeded:
            severity = Severity.CRITICAL
            description = f"Root account performed a privileged action ({event.event_name})."
        else:
            severity = Severity.HIGH
            description = f"Root account attempted an action ({event.event_name})."

        yield self.finding(
            resource=resource, event=event, severity=severity, description=description
        )


@register
class ConsoleLoginWithoutMfa(Rule):
    id = "CONSOLE_LOGIN_WITHOUT_MFA"
    title = "Console login without MFA"
    severity = Severity.MEDIUM
    description = "A successful console sign-in did not use multi-factor authentication."
    remediation = (
        "Enforce MFA for all console users via an IAM policy on aws:MultiFactorAuthPresent. "
        "For root, register a hardware or virtual MFA device immediately."
    )
    event_names = frozenset({"ConsoleLogin"})

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.event_source != _SIGNIN_SOURCE:
            return
        if dig(event.response_elements, "ConsoleLogin") != "Success":
            return
        if str(event.additional_event_data.get("MFAUsed", "")).lower() != "no":
            return
        # Suppress federated / SSO logins where MFA is enforced at the IdP but
        # CloudTrail still records MFAUsed="No".
        if event.actor_type in _FEDERATED_TYPES:
            return
        if event.additional_event_data.get("SamlProviderArn") or event.mfa_authenticated:
            return

        who = "root" if event.is_root else (event.actor_name or "an IAM user")
        severity = Severity.HIGH if event.is_root else Severity.MEDIUM
        yield self.finding(
            resource=event.actor_arn or who,
            event=event,
            severity=severity,
            description=f"Console login by {who} without MFA from {event.source_ip}.",
        )


@register
class ConsoleLoginBruteForce(Rule):
    id = "CONSOLE_LOGIN_BRUTE_FORCE"
    title = "Console login brute force"
    severity = Severity.HIGH
    description = "Repeated failed console logins from a single source (possible brute force)."
    remediation = (
        "Investigate the source IP, enforce MFA and a strong password policy, and consider "
        "restricting console access by network or geography."
    )
    event_names = frozenset({"ConsoleLogin"})

    #: Failures from one source IP at/above this count are reported.
    threshold = 5

    def __init__(self) -> None:
        self._failures: dict[str, int] = {}
        self._successes: set[str] = set()
        self._context: dict[str, CloudTrailEvent] = {}

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.event_source != _SIGNIN_SOURCE:
            return ()
        result = dig(event.response_elements, "ConsoleLogin")
        source = event.source_ip or "unknown"
        if result == "Failure":
            self._failures[source] = self._failures.get(source, 0) + 1
            self._context.setdefault(source, event)
        elif result == "Success":
            self._successes.add(source)
        return ()

    def finalize(self) -> Iterable[Finding]:
        for source, count in sorted(self._failures.items()):
            if count < self.threshold:
                continue
            event = self._context.get(source)
            if source in self._successes:
                yield self.finding(
                    resource=source,
                    event=event,
                    severity=Severity.CRITICAL,
                    description=(
                        f"{count} failed console logins from {source} followed by a successful "
                        "login (possible account takeover)."
                    ),
                )
            else:
                yield self.finding(
                    resource=source,
                    event=event,
                    severity=Severity.HIGH,
                    description=f"{count} failed console logins from {source} (brute force).",
                )


@register
class UnauthorizedApiCalls(Rule):
    id = "UNAUTHORIZED_API_CALLS"
    title = "Unauthorized API activity"
    severity = Severity.LOW
    description = (
        "One principal was denied access across multiple distinct actions (possible enumeration)."
    )
    remediation = (
        "Investigate the principal for compromise or misconfiguration. Rotate its credentials if "
        "unexpected, and review CloudTrail for any successful calls by the same identity."
    )
    # Empty event_names -> inspect every event (this rule keys off errorCode).

    _low_threshold = 3
    _medium_threshold = 5
    _high_threshold = 10

    _DENIED_CODES: ClassVar[set[str]] = {
        "accessdenied",
        "accessdeniedexception",
        "unauthorizedoperation",
        "client.unauthorizedoperation",
        "forbidden",
    }

    def __init__(self) -> None:
        self._actions: dict[str, set[str]] = {}
        self._context: dict[str, CloudTrailEvent] = {}

    @classmethod
    def _is_denied(cls, code: str) -> bool:
        lowered = code.lower()
        return (
            lowered in cls._DENIED_CODES
            or lowered.endswith("notauthorized")
            or lowered.endswith("accessdenied")
            or lowered.endswith("unauthorized")
        )

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if not event.error_code or not self._is_denied(event.error_code):
            return ()
        actor = event.actor_arn or event.source_ip or "unknown-principal"
        self._actions.setdefault(actor, set()).add(f"{event.event_source}:{event.event_name}")
        self._context.setdefault(actor, event)
        return ()

    def finalize(self) -> Iterable[Finding]:
        for actor, actions in sorted(self._actions.items()):
            distinct = len(actions)
            if distinct < self._low_threshold:
                continue
            if distinct >= self._high_threshold:
                severity, label = Severity.HIGH, "broad permission enumeration"
            elif distinct >= self._medium_threshold:
                severity, label = Severity.MEDIUM, "permission enumeration"
            else:
                severity, label = Severity.LOW, "repeated access-denied errors"
            yield self.finding(
                resource=actor,
                event=self._context.get(actor),
                severity=severity,
                description=f"{distinct} distinct denied actions by {actor} ({label}).",
            )
