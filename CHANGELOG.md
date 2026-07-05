# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- SARIF output (`--format sarif`) for GitHub Code Scanning.
- Suppression / allow-list file for known-good principals.
- Roadmap rules: `PASSROLE_TO_PRIVILEGED_ROLE`, `EC2_INSTANCE_LAUNCHED_UNUSUAL_REGION`,
  `AMI_OR_SNAPSHOT_MADE_PUBLIC`, `EBS_DEFAULT_ENCRYPTION_DISABLED`.

## [0.1.0]

### Added
- Offline CloudTrail scanner CLI (`cts`) with `scan`, `rules`, and `version` commands.
- Loader supporting the `Records` envelope, bare arrays, single records, gzip,
  and JSONL, with recursive directory search and `eventID` de-duplication.
- Extensible rule engine: `Rule` base class, `@register` decorator, and package
  auto-discovery (add a rule by dropping one file in `rules/`).
- 14 detection rules across EC2 security groups, IAM, S3, KMS, and logging/threat-
  detection controls, including two correlation rules (brute force, recon).
- JSON (metadata envelope) and rich terminal table output.
- CI-gating exit codes (`--fail-on`) and `--min-severity` / `--rule` / `--exclude-rule` filters.
- pytest suite (unit, data-driven fixture, golden JSON, and CLI tests) with a 90%
  coverage gate; ruff + mypy (strict) configured; GitHub Actions CI.
- Synthetic, public-safe fixtures and an example log.
