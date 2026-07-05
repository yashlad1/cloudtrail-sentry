"""S3 public-exposure rules."""

from __future__ import annotations

from collections.abc import Iterable

from .._util import as_list, iter_statements, parse_policy_document, principal_is_wildcard
from ..events import CloudTrailEvent
from ..models import Finding, Severity
from ..registry import register
from .base import Rule

_S3_SOURCE = "s3.amazonaws.com"

_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_PUBLIC_CANNED_ACLS = {"public-read", "public-read-write"}

# Condition keys that scope a wildcard-principal policy to something specific
# (a CDN, a VPC, an org). Their presence means the grant is likely intentional.
_SCOPING_CONDITION_KEYS = {
    "aws:sourceip",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourcearn",
    "aws:principalorgid",
    "aws:principalorgpaths",
}

# The four S3 Block Public Access flags. Any set false weakens protection.
_PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _is_false(value: object) -> bool:
    return value is False or str(value).lower() == "false"


def _has_scoping_condition(statement: dict[str, object]) -> bool:
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False
    for operands in condition.values():
        if isinstance(operands, dict):
            for key in operands:
                if str(key).lower() in _SCOPING_CONDITION_KEYS:
                    return True
    return False


@register
class S3BucketExposedPublic(Rule):
    id = "S3_BUCKET_EXPOSED_PUBLIC"
    title = "S3 bucket exposed to the public"
    severity = Severity.CRITICAL
    description = "A bucket policy, ACL, or public-access-block change exposed a bucket publicly."
    remediation = (
        "Re-enable S3 Block Public Access at the bucket and account level and remove the public "
        "statement/grant (aws s3api put-public-access-block --bucket <b> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true)."
    )
    event_names = frozenset(
        {
            "PutBucketPolicy",
            "PutBucketAcl",
            "PutBucketPublicAccessBlock",
            "DeletePublicAccessBlock",
        }
    )

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only or event.event_source != _S3_SOURCE:
            return
        bucket = str(event.request_parameters.get("bucketName", "unknown-bucket"))
        handler = {
            "PutBucketPolicy": self._policy,
            "PutBucketAcl": self._acl,
            "PutBucketPublicAccessBlock": self._public_access_block,
            "DeletePublicAccessBlock": self._delete_public_access_block,
        }[event.event_name]
        yield from handler(event, bucket)

    def _policy(self, event: CloudTrailEvent, bucket: str) -> Iterable[Finding]:
        params = event.request_parameters
        policy = parse_policy_document(params.get("bucketPolicy") or params.get("policy"))
        if policy is None:
            return
        for stmt in iter_statements(policy):
            if stmt.get("Effect") != "Allow":
                continue
            if not principal_is_wildcard(stmt.get("Principal")):
                continue
            if _has_scoping_condition(stmt):
                # Wildcard principal but scoped by a condition (e.g. CloudFront, an
                # org, a source IP) — treated as an intentional, restricted grant.
                continue
            yield self.finding(
                resource=bucket,
                event=event,
                severity=Severity.CRITICAL,
                description=(
                    f'Bucket policy on {bucket} allows unconditional public access (Principal "*").'
                ),
            )
            return

    def _acl(self, event: CloudTrailEvent, bucket: str) -> Iterable[Finding]:
        params = event.request_parameters
        canned = str(params.get("x-amz-acl", "")).lower()
        if canned in _PUBLIC_CANNED_ACLS:
            yield self.finding(
                resource=bucket,
                event=event,
                severity=Severity.CRITICAL,
                description=f"Bucket {bucket} set to a public canned ACL ({canned}).",
            )
            return
        grants = _grants(params)
        for grant in grants:
            uri = str(_grantee_uri(grant))
            if uri == _ALL_USERS_URI:
                yield self.finding(
                    resource=bucket,
                    event=event,
                    severity=Severity.CRITICAL,
                    description=f"Bucket ACL on {bucket} grants access to AllUsers (public).",
                )
                return
            if uri == _AUTH_USERS_URI:
                yield self.finding(
                    resource=bucket,
                    event=event,
                    severity=Severity.HIGH,
                    description=(
                        f"Bucket ACL on {bucket} grants access to AuthenticatedUsers "
                        "(any AWS account)."
                    ),
                )
                return

    def _public_access_block(self, event: CloudTrailEvent, bucket: str) -> Iterable[Finding]:
        config = event.request_parameters.get("PublicAccessBlockConfiguration")
        if not isinstance(config, dict):
            return
        weakened = [flag for flag in _PAB_FLAGS if _is_false(config.get(flag))]
        if weakened:
            yield self.finding(
                resource=bucket,
                event=event,
                severity=Severity.HIGH,
                description=(
                    f"Block Public Access weakened on {bucket}: {', '.join(weakened)} set to false."
                ),
            )

    def _delete_public_access_block(self, event: CloudTrailEvent, bucket: str) -> Iterable[Finding]:
        yield self.finding(
            resource=bucket,
            event=event,
            severity=Severity.HIGH,
            description=f"Block Public Access configuration deleted from {bucket}.",
        )


def _grants(params: dict[str, object]) -> list[dict[str, object]]:
    acp = params.get("AccessControlPolicy")
    if not isinstance(acp, dict):
        return []
    acl = acp.get("AccessControlList")
    if not isinstance(acl, dict):
        return []
    return [g for g in as_list(acl.get("Grant")) if isinstance(g, dict)]


def _grantee_uri(grant: dict[str, object]) -> object:
    grantee = grant.get("Grantee")
    if isinstance(grantee, dict):
        return grantee.get("URI", "")
    return ""
