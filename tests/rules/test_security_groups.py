"""Tests for the security-group exposure rule."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cloudtrail_sentry.models import Finding, Severity

RULE = "SECURITY_GROUP_OPEN_TO_INTERNET"

Record = Callable[..., dict[str, Any]]
Run = Callable[..., list[Finding]]


def _ingress(make_record: Record, perm: dict[str, Any]) -> dict[str, Any]:
    return make_record(
        eventName="AuthorizeSecurityGroupIngress",
        eventSource="ec2.amazonaws.com",
        requestParameters={"groupId": "sg-0abcd1234efgh5678", "ipPermissions": {"items": [perm]}},
    )


def _hits(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.rule == RULE]


def test_ssh_open_to_world_is_high(make_record: Record, run: Run) -> None:
    perm = {
        "ipProtocol": "tcp",
        "fromPort": 22,
        "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
    }
    hits = _hits(run(_ingress(make_record, perm)))
    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH
    assert hits[0].resource == "sg-0abcd1234efgh5678"


def test_rdp_over_ipv6_is_high(make_record: Record, run: Run) -> None:
    perm = {
        "ipProtocol": "tcp",
        "fromPort": 3389,
        "toPort": 3389,
        "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]},
    }
    assert _hits(run(_ingress(make_record, perm)))[0].severity == Severity.HIGH


def test_all_ports_open_is_high(make_record: Record, run: Run) -> None:
    perm = {"ipProtocol": "-1", "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}
    hits = _hits(run(_ingress(make_record, perm)))
    assert hits and hits[0].severity == Severity.HIGH


def test_non_sensitive_port_is_medium(make_record: Record, run: Run) -> None:
    perm = {
        "ipProtocol": "tcp",
        "fromPort": 8080,
        "toPort": 8080,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
    }
    hits = _hits(run(_ingress(make_record, perm)))
    assert hits and hits[0].severity == Severity.MEDIUM


def test_specific_cidr_is_not_flagged(make_record: Record, run: Run) -> None:
    perm = {
        "ipProtocol": "tcp",
        "fromPort": 22,
        "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]},
    }
    assert not _hits(run(_ingress(make_record, perm)))


def test_failed_call_is_not_flagged(make_record: Record, run: Run) -> None:
    perm = {
        "ipProtocol": "tcp",
        "fromPort": 22,
        "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
    }
    record = _ingress(make_record, perm)
    record["errorCode"] = "Client.UnauthorizedOperation"
    assert not _hits(run(record))
