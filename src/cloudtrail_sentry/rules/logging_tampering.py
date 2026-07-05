"""Rules for tampering with detective/logging controls (defense evasion)."""

from __future__ import annotations

from collections.abc import Iterable

from ..events import CloudTrailEvent
from ..models import Finding, Severity
from ..registry import register
from .base import Rule


@register
class CloudTrailLoggingDisabled(Rule):
    id = "CLOUDTRAIL_LOGGING_DISABLED"
    title = "CloudTrail logging disabled or deleted"
    severity = Severity.CRITICAL
    description = (
        "CloudTrail logging was stopped, deleted, or narrowed — the audit trail is at risk."
    )
    remediation = (
        "Restart logging (aws cloudtrail start-logging --name <trail>), restore the trail "
        "configuration, and investigate the principal responsible. Treat as defense evasion."
    )
    event_names = frozenset({"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"})

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != "cloudtrail.amazonaws.com":
            return
        params = event.request_parameters
        trail = str(params.get("name", "unknown-trail"))
        name = event.event_name

        if name in ("StopLogging", "DeleteTrail"):
            verb = "stopped" if name == "StopLogging" else "deleted"
            yield self.finding(
                resource=trail,
                event=event,
                description=f"CloudTrail trail {trail} was {verb}.",
            )
        elif name == "UpdateTrail":
            if _is_false(params.get("isMultiRegionTrail")) or _is_false(
                params.get("includeGlobalServiceEvents")
            ):
                yield self.finding(
                    resource=trail,
                    event=event,
                    severity=Severity.HIGH,
                    description=f"Trail {trail} reconfigured to narrow its logging scope.",
                )
        elif name == "PutEventSelectors" and self._excludes_management(params):
            yield self.finding(
                resource=trail,
                event=event,
                severity=Severity.HIGH,
                description=f"Trail {trail} event selectors now exclude management events.",
            )

    @staticmethod
    def _excludes_management(params: dict[str, object]) -> bool:
        selectors = params.get("eventSelectors")
        if not isinstance(selectors, list):
            return False
        for selector in selectors:
            if isinstance(selector, dict) and _is_false(selector.get("includeManagementEvents")):
                return True
        return False


@register
class GuardDutyDisabled(Rule):
    id = "GUARDDUTY_DISABLED"
    title = "GuardDuty threat detection disabled"
    severity = Severity.CRITICAL
    description = "GuardDuty was disabled or its detector deleted, blinding threat detection."
    remediation = (
        "Re-enable GuardDuty immediately (aws guardduty update-detector --enable) and investigate "
        "the principal that disabled it. Treat as an active-incident indicator."
    )
    event_names = frozenset(
        {"DeleteDetector", "UpdateDetector", "StopMonitoringMembers", "DeleteMembers"}
    )

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != "guardduty.amazonaws.com":
            return
        detector = str(event.request_parameters.get("detectorId", "unknown-detector"))
        name = event.event_name

        if name == "DeleteDetector":
            yield self.finding(
                resource=detector,
                event=event,
                description=f"GuardDuty detector {detector} deleted.",
            )
        elif name == "UpdateDetector":
            if _is_false(event.request_parameters.get("enable")):
                yield self.finding(
                    resource=detector,
                    event=event,
                    description=f"GuardDuty detector {detector} disabled (enable=false).",
                )
        else:  # StopMonitoringMembers / DeleteMembers
            yield self.finding(
                resource=detector,
                event=event,
                severity=Severity.HIGH,
                description=f"GuardDuty member monitoring reduced via {name}.",
            )


@register
class AwsConfigDisabled(Rule):
    id = "AWS_CONFIG_DISABLED"
    title = "AWS Config recording disabled"
    severity = Severity.HIGH
    description = (
        "AWS Config recording or delivery was stopped/deleted, removing configuration visibility."
    )
    remediation = (
        "Restart the recorder (aws configservice start-configuration-recorder), restore the "
        "delivery channel, and investigate the change."
    )
    event_names = frozenset(
        {"StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel"}
    )

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != "config.amazonaws.com":
            return
        params = event.request_parameters
        resource = str(
            params.get("configurationRecorderName")
            or params.get("deliveryChannelName")
            or "aws-config"
        )
        yield self.finding(
            resource=resource,
            event=event,
            description=f"AWS Config disabled via {event.event_name}.",
        )


@register
class KmsKeyDisabledOrScheduledDeletion(Rule):
    id = "KMS_KEY_DISABLED_OR_SCHEDULED_DELETION"
    title = "KMS key disabled or scheduled for deletion"
    severity = Severity.HIGH
    description = "A KMS key was disabled or scheduled for deletion (risking encrypted-data loss)."
    remediation = (
        "If unexpected, cancel deletion immediately (aws kms cancel-key-deletion) or re-enable the "
        "key (aws kms enable-key). Data encrypted under a deleted key is unrecoverable."
    )
    event_names = frozenset({"DisableKey", "ScheduleKeyDeletion"})

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != "kms.amazonaws.com":
            return
        key_id = str(event.request_parameters.get("keyId", "unknown-key"))
        if event.event_name == "ScheduleKeyDeletion":
            window = event.request_parameters.get("pendingWindowInDays", "?")
            yield self.finding(
                resource=key_id,
                event=event,
                severity=Severity.CRITICAL,
                description=f"KMS key {key_id} scheduled for deletion in {window} day(s).",
            )
        else:
            yield self.finding(
                resource=key_id,
                event=event,
                severity=Severity.HIGH,
                description=f"KMS key {key_id} disabled.",
            )


def _is_false(value: object) -> bool:
    return value is False or str(value).lower() == "false"
