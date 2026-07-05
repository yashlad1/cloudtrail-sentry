"""Tests for the authentication / access-anomaly rules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cloudtrail_sentry.models import Finding, Severity

Record = Callable[..., dict[str, Any]]
Run = Callable[..., list[Finding]]

_ROOT = {"type": "Root", "arn": "arn:aws:iam::111111111111:root", "accountId": "111111111111"}


def _hits(findings: list[Finding], rule: str) -> list[Finding]:
    return [f for f in findings if f.rule == rule]


def _console(
    make_record: Record,
    *,
    identity: dict[str, Any],
    result: str = "Success",
    mfa: str = "No",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    add = {"MFAUsed": mfa}
    if extra:
        add.update(extra)
    return make_record(
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        eventType="AwsConsoleSignIn",
        responseElements={"ConsoleLogin": result},
        additionalEventData=add,
        userIdentity=identity,
    )


# -- ROOT_ACCOUNT_USED -------------------------------------------------------


def test_root_console_login_is_high(make_record: Record, run: Run) -> None:
    rec = _console(make_record, identity=_ROOT)
    assert _hits(run(rec), "ROOT_ACCOUNT_USED")[0].severity == Severity.HIGH


def test_root_mutation_is_critical(make_record: Record, run: Run) -> None:
    rec = make_record(
        eventName="TerminateInstances",
        eventSource="ec2.amazonaws.com",
        userIdentity=_ROOT,
        readOnly=False,
    )
    assert _hits(run(rec), "ROOT_ACCOUNT_USED")[0].severity == Severity.CRITICAL


def test_root_readonly_is_medium(make_record: Record, run: Run) -> None:
    rec = make_record(eventName="DescribeInstances", userIdentity=_ROOT, readOnly=True)
    assert _hits(run(rec), "ROOT_ACCOUNT_USED")[0].severity == Severity.MEDIUM


def test_root_access_key_is_critical(make_record: Record, run: Run) -> None:
    identity = {**_ROOT, "accessKeyId": "AKIAEXAMPLEROOTKEY0"}
    rec = make_record(eventName="DescribeInstances", userIdentity=identity, readOnly=True)
    assert _hits(run(rec), "ROOT_ACCOUNT_USED")[0].severity == Severity.CRITICAL


def test_service_principal_root_not_flagged(make_record: Record, run: Run) -> None:
    identity = {**_ROOT, "invokedBy": "guardduty.amazonaws.com"}
    rec = make_record(eventName="CreateServiceLinkedRole", userIdentity=identity)
    assert not _hits(run(rec), "ROOT_ACCOUNT_USED")


# -- CONSOLE_LOGIN_WITHOUT_MFA ----------------------------------------------


def test_iam_user_login_without_mfa_is_medium(make_record: Record, run: Run) -> None:
    identity = {"type": "IAMUser", "userName": "bob", "accountId": "111111111111"}
    rec = _console(make_record, identity=identity)
    assert _hits(run(rec), "CONSOLE_LOGIN_WITHOUT_MFA")[0].severity == Severity.MEDIUM


def test_root_login_without_mfa_is_high(make_record: Record, run: Run) -> None:
    rec = _console(make_record, identity=_ROOT)
    assert _hits(run(rec), "CONSOLE_LOGIN_WITHOUT_MFA")[0].severity == Severity.HIGH


def test_login_with_mfa_is_not_flagged(make_record: Record, run: Run) -> None:
    identity = {"type": "IAMUser", "userName": "bob", "accountId": "111111111111"}
    rec = _console(make_record, identity=identity, mfa="Yes")
    assert not _hits(run(rec), "CONSOLE_LOGIN_WITHOUT_MFA")


def test_saml_login_is_not_flagged(make_record: Record, run: Run) -> None:
    identity = {"type": "SAMLUser", "userName": "carol", "accountId": "111111111111"}
    rec = _console(
        make_record,
        identity=identity,
        extra={"SamlProviderArn": "arn:aws:iam::111111111111:saml-provider/Okta"},
    )
    assert not _hits(run(rec), "CONSOLE_LOGIN_WITHOUT_MFA")


# -- UNAUTHORIZED_API_CALLS (recon correlation) -----------------------------


def _denied(make_record: Record, n: int) -> list[dict[str, Any]]:
    pool = [
        ("ec2.amazonaws.com", "DescribeInstances"),
        ("iam.amazonaws.com", "ListUsers"),
        ("s3.amazonaws.com", "ListBuckets"),
        ("kms.amazonaws.com", "ListKeys"),
        ("guardduty.amazonaws.com", "ListDetectors"),
        ("rds.amazonaws.com", "DescribeDBInstances"),
        ("lambda.amazonaws.com", "ListFunctions"),
        ("sns.amazonaws.com", "ListTopics"),
        ("sqs.amazonaws.com", "ListQueues"),
        ("ecs.amazonaws.com", "ListClusters"),
    ]
    return [
        make_record(eventName=name, eventSource=src, readOnly=True, errorCode="AccessDenied")
        for src, name in pool[:n]
    ]


def test_two_denials_not_flagged(make_record: Record, run: Run) -> None:
    assert not _hits(run(_denied(make_record, 2)), "UNAUTHORIZED_API_CALLS")


def test_three_denials_is_low(make_record: Record, run: Run) -> None:
    assert _hits(run(_denied(make_record, 3)), "UNAUTHORIZED_API_CALLS")[0].severity == Severity.LOW


def test_five_denials_is_medium(make_record: Record, run: Run) -> None:
    hits = _hits(run(_denied(make_record, 5)), "UNAUTHORIZED_API_CALLS")
    assert hits[0].severity == Severity.MEDIUM


def test_ten_denials_is_high(make_record: Record, run: Run) -> None:
    hits = _hits(run(_denied(make_record, 10)), "UNAUTHORIZED_API_CALLS")
    assert hits[0].severity == Severity.HIGH
