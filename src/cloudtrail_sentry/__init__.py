"""cloudtrail-sentry: detect suspicious AWS activity in CloudTrail logs.

A dependency-light, offline CLI that reads local AWS CloudTrail JSON logs and
flags risky activity through an extensible rule engine. It makes **no** AWS API
calls and requires **no** credentials — there is nothing to leak by design.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("cloudtrail-sentry")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0+unknown"

from .engine import Engine
from .events import CloudTrailEvent
from .models import ExitCode, Finding, Severity
from .registry import all_rules, register
from .rules.base import Rule

__all__ = [
    "CloudTrailEvent",
    "Engine",
    "ExitCode",
    "Finding",
    "Rule",
    "Severity",
    "__version__",
    "all_rules",
    "register",
]
