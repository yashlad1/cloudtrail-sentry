"""Command-line interface for cloudtrail-sentry (the ``cts`` command)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .engine import Engine
from .loader import LoaderError, iter_events
from .models import ExitCode, Finding, Severity
from .output import OutputFormat, write_report
from .registry import known_rule_ids, rule_classes, select_rules

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Detect suspicious AWS activity in local CloudTrail logs. No AWS credentials required.",
)

_SEVERITY_CHOICES = ", ".join(level.name for level in Severity)


def _parse_severity(value: str, *, option: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint=option) from exc


def _validate_rule_ids(ids: list[str] | None, *, option: str) -> None:
    if not ids:
        return
    known = known_rule_ids()
    unknown = sorted({rid for rid in ids if rid.strip().upper() not in known})
    if unknown:
        raise typer.BadParameter(
            f"unknown rule id(s): {', '.join(unknown)}. Run `cts rules` to list valid ids.",
            param_hint=option,
        )


@app.command()
def scan(
    paths: Annotated[
        list[Path],
        typer.Argument(
            exists=True,
            readable=True,
            help="CloudTrail JSON/JSONL (optionally .gz) files or directories to scan.",
        ),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format."),
    ] = OutputFormat.table,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write output to a file instead of stdout."),
    ] = None,
    min_severity: Annotated[
        str,
        typer.Option(
            "--min-severity", "-s", help=f"Hide findings below this level ({_SEVERITY_CHOICES})."
        ),
    ] = "INFO",
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit non-zero if any finding is at/above this level, or 'never'.",
        ),
    ] = "HIGH",
    rule: Annotated[
        list[str] | None,
        typer.Option("--rule", "-r", help="Only run these rule id(s). Repeatable."),
    ] = None,
    exclude_rule: Annotated[
        list[str] | None,
        typer.Option("--exclude-rule", help="Skip these rule id(s). Repeatable."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit non-zero if any input is missing or malformed."),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress warnings about skipped input."),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable ANSI colors in table output."),
    ] = False,
) -> None:
    """Scan CloudTrail logs and report findings."""
    min_sev = _parse_severity(min_severity, option="--min-severity")
    fail_threshold: Severity | None = (
        None if fail_on.strip().lower() == "never" else _parse_severity(fail_on, option="--fail-on")
    )
    _validate_rule_ids(rule, option="--rule")
    _validate_rule_ids(exclude_rule, option="--exclude-rule")

    rules = select_rules(include=rule, exclude=exclude_rule)

    def warn(message: str) -> None:
        if not quiet:
            typer.echo(f"warning: {message}", err=True)

    engine = Engine(rules, min_severity=min_sev)
    try:
        findings = engine.run(iter_events(paths, strict=strict, warn=warn))
    except LoaderError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(int(ExitCode.RUNTIME)) from exc

    use_color = not no_color and output is None
    if output is not None:
        with output.open("w", encoding="utf-8") as handle:
            write_report(
                findings,
                fmt=output_format,
                events_scanned=engine.events_scanned,
                version=__version__,
                file=handle,
                color=False,
            )
    else:
        write_report(
            findings,
            fmt=output_format,
            events_scanned=engine.events_scanned,
            version=__version__,
            color=use_color,
        )

    raise typer.Exit(_exit_code(findings, fail_threshold))


def _exit_code(findings: list[Finding], fail_threshold: Severity | None) -> int:
    if fail_threshold is None:
        return int(ExitCode.OK)
    if any(finding.severity >= fail_threshold for finding in findings):
        return int(ExitCode.FINDINGS)
    return int(ExitCode.OK)


@app.command()
def rules(
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format."),
    ] = OutputFormat.table,
) -> None:
    """List the detection rule catalog."""
    classes = rule_classes()
    if output_format is OutputFormat.json:
        import json

        catalog = [
            {
                "id": cls.id,
                "title": cls.title,
                "severity": cls.severity.name,
                "description": cls.description,
                "remediation": cls.remediation,
                "event_names": sorted(cls.event_names),
            }
            for cls in classes
        ]
        typer.echo(json.dumps(catalog, indent=2))
        return

    console = Console()
    table = Table(title=f"cloudtrail-sentry rules ({len(classes)})", show_lines=False)
    table.add_column("Rule ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Description", overflow="fold")
    for cls in classes:
        table.add_row(cls.id, cls.severity.name, cls.description or cls.title)
    console.print(table)


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)


def main() -> None:
    """Console-script entry point (``cts``)."""
    app()


if __name__ == "__main__":
    main()
