"""End-to-end CLI tests (exit codes, formats, filters)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cloudtrail_sentry import __version__
from cloudtrail_sentry.cli import app

runner = CliRunner()


def _examples(fixtures_dir: Path) -> Path:
    return fixtures_dir.parent.parent / "examples" / "sample_cloudtrail.json"


def test_scan_clean_baseline_exits_ok(fixtures_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixtures_dir / "clean_baseline.json")])
    assert result.exit_code == 0


def test_scan_findings_exit_one(fixtures_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixtures_dir / "noisy_incident.json"), "--fail-on", "HIGH"]
    )
    assert result.exit_code == 1


def test_scan_fail_on_never_exits_ok(fixtures_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixtures_dir / "noisy_incident.json"), "--fail-on", "never"]
    )
    assert result.exit_code == 0


def test_scan_json_output_to_file(fixtures_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app, ["scan", str(_examples(fixtures_dir)), "-f", "json", "-o", str(out)]
    )
    assert result.exit_code == 1  # example log contains a CRITICAL finding
    report = json.loads(out.read_text())
    assert report["summary"]["findings"] == 3
    assert report["summary"]["by_severity"] == {"CRITICAL": 1, "HIGH": 2}


def test_scan_min_severity_filters(fixtures_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "f.json"
    runner.invoke(
        app,
        [
            "scan",
            str(fixtures_dir / "noisy_incident.json"),
            "-s",
            "CRITICAL",
            "-f",
            "json",
            "-o",
            str(out),
            "--fail-on",
            "never",
        ],
    )
    report = json.loads(out.read_text())
    assert report["findings"]
    assert all(f["severity"] == "CRITICAL" for f in report["findings"])


def test_scan_single_rule_filter(fixtures_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "f.json"
    runner.invoke(
        app,
        [
            "scan",
            str(fixtures_dir / "noisy_incident.json"),
            "-r",
            "SECURITY_GROUP_OPEN_TO_INTERNET",
            "-f",
            "json",
            "-o",
            str(out),
            "--fail-on",
            "never",
        ],
    )
    report = json.loads(out.read_text())
    assert {f["rule"] for f in report["findings"]} == {"SECURITY_GROUP_OPEN_TO_INTERNET"}


def test_bad_min_severity_is_usage_error(fixtures_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixtures_dir / "clean_baseline.json"), "-s", "bogus"])
    assert result.exit_code == 2


def test_unknown_rule_is_usage_error(fixtures_dir: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixtures_dir / "clean_baseline.json"), "-r", "NOPE"])
    assert result.exit_code == 2


def test_nonexistent_path_is_usage_error() -> None:
    result = runner.invoke(app, ["scan", "/no/such/path.json"])
    assert result.exit_code == 2


def test_strict_malformed_is_runtime_error(fixtures_dir: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(fixtures_dir / "malformed" / "truncated.json"), "--strict"]
    )
    assert result.exit_code == 3


def test_rules_command_lists_catalog() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "SECURITY_GROUP_OPEN_TO_INTERNET" in result.output
    assert "14" in result.output


def test_rules_json_lists_all() -> None:
    result = runner.invoke(app, ["rules", "-f", "json"])
    assert result.exit_code == 0
    catalog = json.loads(result.output)
    assert len(catalog) == 14
    assert {"id", "severity", "remediation", "event_names"} <= catalog[0].keys()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.output.strip() == __version__


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "rules" in result.output
