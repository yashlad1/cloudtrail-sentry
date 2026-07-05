"""Tests for the IAM privilege-escalation and persistence rules."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from cloudtrail_sentry.models import Finding, Severity

Record = Callable[..., dict[str, Any]]
Run = Callable[..., list[Finding]]


def _hits(findings: list[Finding], rule: str) -> list[Finding]:
    return [f for f in findings if f.rule == rule]


def _iam(make_record: Record, name: str, params: dict[str, Any], **over: Any) -> dict[str, Any]:
    return make_record(
        eventName=name, eventSource="iam.amazonaws.com", requestParameters=params, **over
    )


def test_attach_administrator_access_is_critical(make_record: Record, run: Run) -> None:
    rec = _iam(
        make_record,
        "AttachUserPolicy",
        {"userName": "eve", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    hits = _hits(run(rec), "IAM_ADMIN_POLICY_ATTACHED")
    assert hits and hits[0].severity == Severity.CRITICAL
    assert hits[0].resource == "eve"


def test_attach_power_user_is_high(make_record: Record, run: Run) -> None:
    rec = _iam(
        make_record,
        "AttachRolePolicy",
        {"roleName": "r", "policyArn": "arn:aws:iam::aws:policy/PowerUserAccess"},
    )
    hits = _hits(run(rec), "IAM_ADMIN_POLICY_ATTACHED")
    assert hits and hits[0].severity == Severity.HIGH


def test_attach_scoped_policy_is_not_flagged(make_record: Record, run: Run) -> None:
    rec = _iam(
        make_record,
        "AttachUserPolicy",
        {"userName": "eve", "policyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
    )
    assert not _hits(run(rec), "IAM_ADMIN_POLICY_ATTACHED")


def test_inline_wildcard_policy_is_critical(make_record: Record, run: Run) -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    rec = _iam(
        make_record,
        "PutUserPolicy",
        {"userName": "eve", "policyName": "p", "policyDocument": quote(json.dumps(doc))},
    )
    hits = _hits(run(rec), "IAM_ADMIN_POLICY_ATTACHED")
    assert hits and hits[0].severity == Severity.CRITICAL


def test_inline_scoped_policy_is_not_flagged(make_record: Record, run: Run) -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
        ],
    }
    rec = _iam(
        make_record, "PutRolePolicy", {"roleName": "r", "policyName": "p", "policyDocument": doc}
    )
    assert not _hits(run(rec), "IAM_ADMIN_POLICY_ATTACHED")


def test_access_key_for_self_is_high(make_record: Record, run: Run) -> None:
    rec = _iam(
        make_record,
        "CreateAccessKey",
        {"userName": "alice"},
        responseElements={"accessKey": {"userName": "alice", "accessKeyId": "AKIAEXAMPLE0"}},
    )
    hits = _hits(run(rec), "IAM_ACCESS_KEY_CREATED")
    assert hits and hits[0].severity == Severity.HIGH


def test_access_key_for_other_user_is_critical(make_record: Record, run: Run) -> None:
    rec = _iam(
        make_record,
        "CreateAccessKey",
        {"userName": "eve"},
        responseElements={"accessKey": {"userName": "eve", "accessKeyId": "AKIAEXAMPLE1"}},
    )
    hits = _hits(run(rec), "IAM_ACCESS_KEY_CREATED")
    assert hits and hits[0].severity == Severity.CRITICAL


def test_create_user_is_medium(make_record: Record, run: Run) -> None:
    rec = _iam(
        make_record,
        "CreateUser",
        {"userName": "eve"},
        responseElements={"user": {"userName": "eve"}},
    )
    hits = _hits(run(rec), "IAM_USER_CREATED")
    assert hits and hits[0].severity == Severity.MEDIUM


def test_trust_policy_to_wildcard_is_critical(make_record: Record, run: Run) -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
    }
    rec = _iam(
        make_record,
        "UpdateAssumeRolePolicy",
        {"roleName": "AppRole", "policyDocument": quote(json.dumps(doc))},
    )
    hits = _hits(run(rec), "IAM_ROLE_TRUST_POLICY_MODIFIED")
    assert hits and hits[0].severity == Severity.CRITICAL


def test_trust_policy_to_external_account_is_high(make_record: Record, run: Run) -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    rec = _iam(
        make_record, "UpdateAssumeRolePolicy", {"roleName": "AppRole", "policyDocument": doc}
    )
    hits = _hits(run(rec), "IAM_ROLE_TRUST_POLICY_MODIFIED")
    assert hits and hits[0].severity == Severity.HIGH


def test_trust_policy_to_own_account_is_not_flagged(make_record: Record, run: Run) -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    rec = _iam(
        make_record, "UpdateAssumeRolePolicy", {"roleName": "AppRole", "policyDocument": doc}
    )
    assert not _hits(run(rec), "IAM_ROLE_TRUST_POLICY_MODIFIED")


def test_failed_attach_is_not_flagged(make_record: Record, run: Run) -> None:
    rec = _iam(
        make_record,
        "AttachUserPolicy",
        {"userName": "eve", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        errorCode="AccessDenied",
    )
    assert not _hits(run(rec), "IAM_ADMIN_POLICY_ATTACHED")
