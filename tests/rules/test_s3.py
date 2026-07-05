"""Tests for the S3 public-exposure rule."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cloudtrail_sentry.models import Finding, Severity

RULE = "S3_BUCKET_EXPOSED_PUBLIC"
_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

Record = Callable[..., dict[str, Any]]
Run = Callable[..., list[Finding]]


def _s3(make_record: Record, name: str, params: dict[str, Any], **over: Any) -> dict[str, Any]:
    return make_record(
        eventName=name, eventSource="s3.amazonaws.com", requestParameters=params, **over
    )


def _hits(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.rule == RULE]


def _public_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        ],
    }


def test_public_bucket_policy_is_critical(make_record: Record, run: Run) -> None:
    rec = _s3(make_record, "PutBucketPolicy", {"bucketName": "b", "bucketPolicy": _public_policy()})
    hits = _hits(run(rec))
    assert hits and hits[0].severity == Severity.CRITICAL
    assert hits[0].resource == "b"


def test_public_policy_with_condition_is_not_flagged(make_record: Record, run: Run) -> None:
    policy = _public_policy()
    policy["Statement"][0]["Condition"] = {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}
    rec = _s3(make_record, "PutBucketPolicy", {"bucketName": "b", "bucketPolicy": policy})
    assert not _hits(run(rec))


def test_acl_all_users_is_critical(make_record: Record, run: Run) -> None:
    rec = _s3(
        make_record,
        "PutBucketAcl",
        {
            "bucketName": "b",
            "AccessControlPolicy": {
                "AccessControlList": {
                    "Grant": [{"Grantee": {"URI": _ALL_USERS}, "Permission": "READ"}]
                }
            },
        },
    )
    hits = _hits(run(rec))
    assert hits and hits[0].severity == Severity.CRITICAL


def test_acl_authenticated_users_is_high(make_record: Record, run: Run) -> None:
    rec = _s3(
        make_record,
        "PutBucketAcl",
        {
            "bucketName": "b",
            "AccessControlPolicy": {
                "AccessControlList": {
                    "Grant": [{"Grantee": {"URI": _AUTH_USERS}, "Permission": "READ"}]
                }
            },
        },
    )
    hits = _hits(run(rec))
    assert hits and hits[0].severity == Severity.HIGH


def test_canned_public_acl_is_critical(make_record: Record, run: Run) -> None:
    rec = _s3(make_record, "PutBucketAcl", {"bucketName": "b", "x-amz-acl": "public-read"})
    hits = _hits(run(rec))
    assert hits and hits[0].severity == Severity.CRITICAL


def test_public_access_block_weakened_is_high(make_record: Record, run: Run) -> None:
    rec = _s3(
        make_record,
        "PutBucketPublicAccessBlock",
        {
            "bucketName": "b",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        },
    )
    hits = _hits(run(rec))
    assert hits and hits[0].severity == Severity.HIGH


def test_public_access_block_hardened_is_not_flagged(make_record: Record, run: Run) -> None:
    rec = _s3(
        make_record,
        "PutBucketPublicAccessBlock",
        {
            "bucketName": "b",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        },
    )
    assert not _hits(run(rec))


def test_delete_public_access_block_is_high(make_record: Record, run: Run) -> None:
    rec = _s3(make_record, "DeletePublicAccessBlock", {"bucketName": "b"})
    hits = _hits(run(rec))
    assert hits and hits[0].severity == Severity.HIGH


def test_failed_call_is_not_flagged(make_record: Record, run: Run) -> None:
    rec = _s3(
        make_record,
        "PutBucketPolicy",
        {"bucketName": "b", "bucketPolicy": _public_policy()},
        errorCode="AccessDenied",
    )
    assert not _hits(run(rec))
