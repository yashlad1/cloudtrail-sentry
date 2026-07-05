"""IAM privilege-escalation and persistence rules."""

from __future__ import annotations

from collections.abc import Iterable

from .._util import (
    as_list,
    dig,
    iter_statements,
    parse_policy_document,
    principal_is_wildcard,
)
from ..events import CloudTrailEvent
from ..models import Finding, Severity
from ..registry import register
from .base import Rule

_IAM_SOURCE = "iam.amazonaws.com"

_ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
_HIGH_RISK_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/PowerUserAccess": "PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess": "IAMFullAccess",
}

_ATTACH_EVENTS = frozenset({"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"})
_INLINE_EVENTS = frozenset(
    {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicyVersion"}
)


def _target_principal(params: dict[str, object]) -> str:
    for key in ("userName", "roleName", "groupName", "policyArn", "policyName"):
        value = params.get(key)
        if value:
            return str(value)
    return "unknown-principal"


def _statement_grants_admin(statement: dict[str, object]) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    actions = [str(a) for a in as_list(statement.get("Action"))]
    resources = [str(r) for r in as_list(statement.get("Resource"))]
    action_is_admin = any(a in ("*", "*:*", "iam:*") for a in actions)
    resource_is_all = any(r == "*" for r in resources)
    return action_is_admin and resource_is_all


@register
class IamAdminPolicyAttached(Rule):
    id = "IAM_ADMIN_POLICY_ATTACHED"
    title = "Administrator-level IAM permissions granted"
    severity = Severity.CRITICAL
    description = "AdministratorAccess (or an inline Action:* / Resource:* grant) was attached."
    remediation = (
        "Detach the administrator policy and grant only the specific actions and resources "
        "required (least privilege). Investigate who performed the change."
    )
    event_names = _ATTACH_EVENTS | _INLINE_EVENTS

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != _IAM_SOURCE:
            return
        if event.event_name in _ATTACH_EVENTS:
            yield from self._managed(event)
        else:
            yield from self._inline(event)

    def _managed(self, event: CloudTrailEvent) -> Iterable[Finding]:
        params = event.request_parameters
        arn = str(params.get("policyArn", ""))
        target = _target_principal(params)
        if arn == _ADMIN_POLICY_ARN:
            yield self.finding(
                resource=target,
                event=event,
                severity=Severity.CRITICAL,
                description=f"AdministratorAccess managed policy attached to {target}.",
            )
        elif arn in _HIGH_RISK_POLICY_ARNS:
            name = _HIGH_RISK_POLICY_ARNS[arn]
            yield self.finding(
                resource=target,
                event=event,
                severity=Severity.HIGH,
                description=f"{name} managed policy attached to {target}.",
                remediation=(
                    "Grant only the specific actions required rather than the broad "
                    f"{name} managed policy."
                ),
            )

    def _inline(self, event: CloudTrailEvent) -> Iterable[Finding]:
        policy = parse_policy_document(event.request_parameters.get("policyDocument"))
        if policy is None:
            return
        if any(_statement_grants_admin(stmt) for stmt in iter_statements(policy)):
            target = _target_principal(event.request_parameters)
            yield self.finding(
                resource=target,
                event=event,
                severity=Severity.CRITICAL,
                description=f"Inline policy granting Action:* on Resource:* applied to {target}.",
            )


@register
class IamAccessKeyCreated(Rule):
    id = "IAM_ACCESS_KEY_CREATED"
    title = "IAM access key created"
    severity = Severity.HIGH
    description = "A long-lived IAM access key was created (a common persistence vector)."
    remediation = (
        "Confirm the key was expected. If not, deactivate and delete it "
        "(aws iam update-access-key --status Inactive; aws iam delete-access-key) "
        "and rotate the user's credentials."
    )
    event_names = frozenset({"CreateAccessKey"})

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != _IAM_SOURCE:
            return
        resp_key = dig(event.response_elements, "accessKey", default={})
        target_user = resp_key.get("userName") or event.request_parameters.get("userName")
        key_id = resp_key.get("accessKeyId", "unknown-key")
        caller = event.actor_name
        resource = f"{target_user or caller or 'self'}:{key_id}"
        if target_user and caller and str(target_user) != caller:
            yield self.finding(
                resource=resource,
                event=event,
                severity=Severity.CRITICAL,
                description=f"{caller} created an access key for a different user ({target_user}).",
            )
        else:
            owner = target_user or caller or "a user"
            yield self.finding(
                resource=resource,
                event=event,
                description=f"Long-lived access key created for {owner}.",
            )


@register
class IamUserCreated(Rule):
    id = "IAM_USER_CREATED"
    title = "New IAM user created"
    severity = Severity.MEDIUM
    description = (
        "A new IAM user was created; verify it was provisioned through an approved process."
    )
    remediation = (
        "Confirm the new user is expected. If not, delete the user and its credentials "
        "and investigate the principal that created it."
    )
    event_names = frozenset({"CreateUser"})

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != _IAM_SOURCE:
            return
        name = (
            dig(event.response_elements, "user", "userName")
            or event.request_parameters.get("userName")
            or "unknown-user"
        )
        yield self.finding(
            resource=str(name),
            event=event,
            description=f"IAM user {name} created.",
        )


@register
class IamRoleTrustPolicyModified(Rule):
    id = "IAM_ROLE_TRUST_POLICY_MODIFIED"
    title = "IAM role trust policy widened"
    severity = Severity.HIGH
    description = "A role's trust policy was opened to a wildcard or an external account."
    remediation = (
        "Restore a least-privilege trust policy scoped to specific trusted principals, and "
        "confirm the change did not create unintended cross-account access."
    )
    event_names = frozenset({"UpdateAssumeRolePolicy"})

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != _IAM_SOURCE:
            return
        policy = parse_policy_document(event.request_parameters.get("policyDocument"))
        if policy is None:
            return
        role = str(event.request_parameters.get("roleName", "unknown-role"))
        result = self._assess(policy, event.account_id)
        if result is None:
            return
        severity, reason = result
        yield self.finding(
            resource=role,
            event=event,
            severity=severity,
            description=f"Trust policy for role {role} now allows assumption by {reason}.",
        )

    @staticmethod
    def _assess(policy: dict[str, object], own_account: str | None) -> tuple[Severity, str] | None:
        external: str | None = None
        for stmt in iter_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            if principal_is_wildcard(principal):
                return Severity.CRITICAL, 'any AWS principal ("*")'
            for entry in _aws_principals(principal):
                account = _account_id_from_principal(entry)
                if account and own_account and account != own_account:
                    external = account
        if external is not None:
            return Severity.HIGH, f"an external account ({external})"
        return None


def _aws_principals(principal: object) -> list[str]:
    if isinstance(principal, dict):
        return [str(p) for p in as_list(principal.get("AWS"))]
    if isinstance(principal, str):
        return [principal]
    return []


def _account_id_from_principal(principal: str) -> str | None:
    if principal.isdigit() and len(principal) == 12:
        return principal
    parts = principal.split(":")
    if len(parts) >= 5 and parts[4].isdigit():
        return parts[4]
    return None
