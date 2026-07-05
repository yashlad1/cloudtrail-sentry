"""The normalized CloudTrail event model.

``CloudTrailEvent`` flattens the handful of top-level fields rules need most,
keeps the free-form ``requestParameters`` / ``responseElements`` as dicts for
rule-specific inspection, and exposes a few derived properties for the
attribution and false-positive checks that nearly every rule shares.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# AWS service-linked roles carry this marker in their ARN; actions performed by
# them are AWS automation, not a human threat.
_SERVICE_ROLE_MARKER = "AWSServiceRoleFor"


@dataclass(frozen=True, slots=True)
class CloudTrailEvent:
    """A single normalized CloudTrail record."""

    event_name: str
    event_source: str
    event_time: str | None = None
    region: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    account_id: str | None = None
    actor_arn: str | None = None
    actor_type: str | None = None
    access_key_id: str | None = None
    invoked_by: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    read_only: bool | None = None
    event_id: str | None = None
    event_type: str | None = None
    request_parameters: dict[str, Any] = field(default_factory=dict)
    response_elements: dict[str, Any] = field(default_factory=dict)
    additional_event_data: dict[str, Any] = field(default_factory=dict)
    user_identity: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_record(cls, rec: dict[str, Any]) -> CloudTrailEvent:
        """Build an event from a raw CloudTrail record, tolerating missing keys."""
        ui = rec.get("userIdentity") or {}
        return cls(
            event_name=rec.get("eventName", ""),
            event_source=rec.get("eventSource", ""),
            event_time=rec.get("eventTime"),
            region=rec.get("awsRegion"),
            source_ip=rec.get("sourceIPAddress"),
            user_agent=rec.get("userAgent"),
            account_id=rec.get("recipientAccountId") or ui.get("accountId"),
            actor_arn=ui.get("arn"),
            actor_type=ui.get("type"),
            access_key_id=ui.get("accessKeyId"),
            invoked_by=ui.get("invokedBy"),
            error_code=rec.get("errorCode"),
            error_message=rec.get("errorMessage"),
            read_only=rec.get("readOnly"),
            event_id=rec.get("eventID"),
            event_type=rec.get("eventType"),
            request_parameters=rec.get("requestParameters") or {},
            response_elements=rec.get("responseElements") or {},
            additional_event_data=rec.get("additionalEventData") or {},
            user_identity=ui,
            raw=rec,
        )

    # -- derived attribution / suppression helpers ---------------------------

    @property
    def succeeded(self) -> bool:
        """True when the API call succeeded (no ``errorCode`` recorded)."""
        return not self.error_code

    @property
    def failed(self) -> bool:
        """True when the API call failed (an ``errorCode`` is present)."""
        return bool(self.error_code)

    @property
    def is_read_only(self) -> bool:
        """True only when the record is explicitly marked read-only."""
        return self.read_only is True

    @property
    def is_root(self) -> bool:
        """True when the caller is the account root user."""
        return self.actor_type == "Root"

    @property
    def actor_name(self) -> str | None:
        """Resolve the human/role name behind the call.

        For assumed roles the top-level ``userName`` is absent, so fall back to
        the session issuer (the role name).
        """
        name = self.user_identity.get("userName")
        if name:
            return str(name)
        issuer = self.user_identity.get("sessionContext", {})
        if isinstance(issuer, dict):
            si = issuer.get("sessionIssuer")
            if isinstance(si, dict) and si.get("userName"):
                return str(si["userName"])
        return None

    @property
    def mfa_authenticated(self) -> bool:
        """True when the session's temporary credentials were MFA-authenticated."""
        ctx = self.user_identity.get("sessionContext")
        if isinstance(ctx, dict):
            attrs = ctx.get("attributes")
            if isinstance(attrs, dict):
                return str(attrs.get("mfaAuthenticated", "")).lower() == "true"
        return False

    @property
    def is_service_principal(self) -> bool:
        """True when the actor is AWS itself (service principal / service-linked role).

        Such actions are AWS automation, not human activity, and most rules
        should suppress them to avoid noise.
        """
        if self.actor_type == "AWSService":
            return True
        if self.invoked_by:
            return True
        ctx = self.user_identity.get("sessionContext")
        if isinstance(ctx, dict):
            si = ctx.get("sessionIssuer")
            if isinstance(si, dict) and _SERVICE_ROLE_MARKER in str(si.get("arn", "")):
                return True
        return False
