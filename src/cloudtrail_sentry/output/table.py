"""Human-readable terminal output using rich tables."""

from __future__ import annotations

from collections.abc import Sequence

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import Finding, Severity
from .json_out import severity_counts

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _summary_text(findings: Sequence[Finding], events_scanned: int) -> Text:
    if not findings:
        return Text(f"Scanned {events_scanned} event(s) — no findings.", style="green")
    counts = severity_counts(findings)
    breakdown = ", ".join(f"{count} {level}" for level, count in counts.items())
    return Text(
        f"Scanned {events_scanned} event(s) — {len(findings)} finding(s): {breakdown}.",
        style="bold",
    )


def build_table(findings: Sequence[Finding]) -> Table:
    """Build the rich table of findings (severity, rule, resource, detail)."""
    table = Table(
        title="cloudtrail-sentry findings",
        box=box.SQUARE,
        show_lines=True,
        expand=False,
        title_justify="left",
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Resource", overflow="fold")
    table.add_column("Detail", overflow="fold", ratio=1)

    for finding in findings:
        detail = finding.description or finding.title
        if finding.remediation:
            detail = f"{detail}\nFix: {finding.remediation}"
        table.add_row(
            Text(finding.severity.name, style=_SEVERITY_STYLE.get(finding.severity, "")),
            finding.rule,
            finding.resource,
            detail,
        )
    return table


def render_table(
    findings: Sequence[Finding], *, events_scanned: int, console: Console | None = None
) -> None:
    """Print a findings summary and table to ``console`` (stdout by default)."""
    console = console or Console()
    console.print(_summary_text(findings, events_scanned))
    if findings:
        console.print(build_table(findings))


def render_table_str(findings: Sequence[Finding], *, events_scanned: int, width: int = 100) -> str:
    """Render the table to a deterministic, uncolored string (used by golden tests)."""
    from io import StringIO

    buffer = StringIO()
    console = Console(file=buffer, width=width, no_color=True, highlight=False, emoji=False)
    render_table(findings, events_scanned=events_scanned, console=console)
    return buffer.getvalue()
