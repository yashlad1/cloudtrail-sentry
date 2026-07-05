"""EC2 security group exposure rules."""

from __future__ import annotations

from collections.abc import Iterable

from .._util import ec2_items
from ..events import CloudTrailEvent
from ..models import Finding, Severity
from ..registry import register
from .base import Rule

_OPEN_V4 = "0.0.0.0/0"
_OPEN_V6 = "::/0"

# Ports whose public exposure is high-risk (remote admin, databases, caches).
_SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _covered_sensitive_ports(from_port: object, to_port: object) -> list[int]:
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return []
    return [port for port in sorted(_SENSITIVE_PORTS) if from_port <= port <= to_port]


def _port_label(from_port: object, to_port: object) -> str:
    if isinstance(from_port, int) and isinstance(to_port, int):
        return f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
    return "an unspecified port range"


@register
class SecurityGroupOpenToInternet(Rule):
    id = "SECURITY_GROUP_OPEN_TO_INTERNET"
    title = "Security group ingress opened to the internet"
    severity = Severity.HIGH
    description = "Inbound rule exposes a port to 0.0.0.0/0 or ::/0."
    remediation = (
        "Restrict the ingress rule to a specific trusted CIDR instead of 0.0.0.0/0 or ::/0; "
        "prefer SSM Session Manager or a bastion host for administrative access."
    )
    event_names = frozenset({"AuthorizeSecurityGroupIngress"})

    def evaluate(self, event: CloudTrailEvent) -> Iterable[Finding]:
        if event.failed or event.is_read_only:
            return
        if event.event_source != "ec2.amazonaws.com":
            return
        params = event.request_parameters
        group = params.get("groupId") or params.get("groupName") or "unknown-security-group"
        for perm in ec2_items(params.get("ipPermissions")):
            open_ranges = self._open_ranges(perm)
            if not open_ranges:
                continue
            severity, exposure = self._classify(perm)
            yield self.finding(
                resource=str(group),
                event=event,
                severity=severity,
                description=f"{exposure} exposed to {', '.join(open_ranges)}.",
            )

    @staticmethod
    def _open_ranges(perm: dict[str, object]) -> list[str]:
        ranges: list[str] = []
        for entry in ec2_items(perm.get("ipRanges")):
            if entry.get("cidrIp") == _OPEN_V4:
                ranges.append(_OPEN_V4)
        for entry in ec2_items(perm.get("ipv6Ranges")):
            if entry.get("cidrIpv6") == _OPEN_V6:
                ranges.append(_OPEN_V6)
        return ranges

    @staticmethod
    def _classify(perm: dict[str, object]) -> tuple[Severity, str]:
        protocol = str(perm.get("ipProtocol", ""))
        if protocol == "-1":
            return Severity.HIGH, "All ports (all protocols)"
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")
        covered = _covered_sensitive_ports(from_port, to_port)
        if covered:
            names = ", ".join(f"{_SENSITIVE_PORTS[p]} ({p})" for p in covered)
            return Severity.HIGH, names
        return Severity.MEDIUM, _port_label(from_port, to_port).capitalize()
