"""Output rendering: JSON envelope and rich terminal table."""

from __future__ import annotations

import enum
import sys
from collections.abc import Sequence
from typing import TextIO

from rich.console import Console

from ..models import Finding
from .json_out import build_report, render_json, severity_counts
from .table import render_table, render_table_str

__all__ = [
    "OutputFormat",
    "build_report",
    "render_json",
    "render_table",
    "render_table_str",
    "severity_counts",
    "write_report",
]


class OutputFormat(str, enum.Enum):
    """Supported ``--format`` values."""

    table = "table"
    json = "json"


def write_report(
    findings: Sequence[Finding],
    *,
    fmt: OutputFormat,
    events_scanned: int,
    version: str,
    file: TextIO | None = None,
    color: bool = True,
) -> None:
    """Write findings to ``file`` (stdout by default) in the requested format.

    JSON is emitted as plain text (pipe-friendly for ``jq``); the table is
    rendered with rich.
    """
    stream = file if file is not None else sys.stdout
    if fmt is OutputFormat.json:
        stream.write(render_json(findings, events_scanned=events_scanned, version=version))
        stream.write("\n")
    else:
        console = Console(file=stream, no_color=not color, highlight=False)
        render_table(findings, events_scanned=events_scanned, console=console)
