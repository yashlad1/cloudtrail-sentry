# Fixture expectations

All fixtures are **synthetic** and safe for a public repo: placeholder account IDs
(`111111111111`, `222222222222`), RFC 5737 documentation IPs (`203.0.113.x`,
`198.51.100.x`, `192.0.2.x`), and fake resource identifiers.

## `events/` — one positive per rule

Each file is named after the rule it must trigger; the scanner must report that
rule when the file is scanned. (`root_account_used.json` also legitimately fires
`CONSOLE_LOGIN_WITHOUT_MFA`, since a root console login is both.)

| File | Expected rule |
| --- | --- |
| `security_group_open_to_internet.json` | `SECURITY_GROUP_OPEN_TO_INTERNET` (HIGH) |
| `iam_admin_policy_attached.json` | `IAM_ADMIN_POLICY_ATTACHED` (CRITICAL) |
| `iam_access_key_created.json` | `IAM_ACCESS_KEY_CREATED` (CRITICAL — key for another user) |
| `iam_user_created.json` | `IAM_USER_CREATED` (MEDIUM) |
| `iam_role_trust_policy_modified.json` | `IAM_ROLE_TRUST_POLICY_MODIFIED` (CRITICAL — trust to `*`) |
| `cloudtrail_logging_disabled.json` | `CLOUDTRAIL_LOGGING_DISABLED` (CRITICAL) |
| `guardduty_disabled.json` | `GUARDDUTY_DISABLED` (CRITICAL) |
| `aws_config_disabled.json` | `AWS_CONFIG_DISABLED` (HIGH) |
| `kms_key_disabled_or_scheduled_deletion.json` | `KMS_KEY_DISABLED_OR_SCHEDULED_DELETION` (CRITICAL) |
| `s3_bucket_exposed_public.json` | `S3_BUCKET_EXPOSED_PUBLIC` (CRITICAL) |
| `root_account_used.json` | `ROOT_ACCOUNT_USED` (HIGH) + `CONSOLE_LOGIN_WITHOUT_MFA` (HIGH) |
| `console_login_without_mfa.json` | `CONSOLE_LOGIN_WITHOUT_MFA` (MEDIUM) |
| `console_login_brute_force.json` | `CONSOLE_LOGIN_BRUTE_FORCE` (HIGH — 6 failures) |
| `unauthorized_api_calls.json` | `UNAUTHORIZED_API_CALLS` (MEDIUM — 5 denied actions) |

## `negatives/` — must produce **zero** findings (false-positive guards)

| File | Why it must not fire |
| --- | --- |
| `sg_open_but_failed.json` | Open-to-world ingress but the call **failed** (`errorCode`). |
| `s3_public_access_block_enabled.json` | Block Public Access set all-true (hardening, not weakening). |
| `s3_policy_public_with_condition.json` | Wildcard principal but scoped by an `aws:SourceIp` condition. |
| `console_login_with_mfa.json` | Console login used MFA. |
| `console_login_saml_no_mfa.json` | SAML/SSO login (MFA enforced at the IdP). |
| `readonly_describe.json` | Read-only Describe/List/Get calls. |
| `service_linked_role.json` | Action performed by an AWS service-linked role. |

## `malformed/` — parser robustness (skipped by default, raise under `--strict`)

| File | Content |
| --- | --- |
| `truncated.json` | Invalid JSON (truncated). |
| `missing_records_key.json` | JSON object with no `Records` array. |
| `not_an_object.json` | Top-level JSON is a bare number. |

## Aggregate fixtures

- `clean_baseline.json` — entirely benign traffic; **zero** findings (the FP canary).
- `noisy_incident.json` — a coherent attack chain firing **9 distinct rules**:
  `ROOT_ACCOUNT_USED`, `CONSOLE_LOGIN_WITHOUT_MFA`, `IAM_USER_CREATED`,
  `IAM_ACCESS_KEY_CREATED`, `IAM_ADMIN_POLICY_ATTACHED`,
  `SECURITY_GROUP_OPEN_TO_INTERNET`, `S3_BUCKET_EXPOSED_PUBLIC`,
  `CLOUDTRAIL_LOGGING_DISABLED`, `GUARDDUTY_DISABLED`.
- `../../examples/sample_cloudtrail.json` — 12 events, 3 findings (1 CRITICAL, 2 HIGH);
  golden output in `golden/sample_findings.json`.
