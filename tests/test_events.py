"""Tests for the CloudTrailEvent normalization and derived properties."""

from __future__ import annotations

from cloudtrail_sentry.events import CloudTrailEvent


def test_missing_fields_default_safely() -> None:
    event = CloudTrailEvent.from_record({})
    assert event.event_name == ""
    assert event.request_parameters == {}
    assert event.succeeded is True
    assert event.is_read_only is False
    assert event.actor_name is None
    assert event.mfa_authenticated is False
    assert event.is_service_principal is False


def test_error_code_marks_failure() -> None:
    event = CloudTrailEvent.from_record({"errorCode": "AccessDenied"})
    assert event.failed is True
    assert event.succeeded is False


def test_read_only_flag() -> None:
    assert CloudTrailEvent.from_record({"readOnly": True}).is_read_only is True
    assert CloudTrailEvent.from_record({"readOnly": False}).is_read_only is False


def test_iam_user_actor_name() -> None:
    event = CloudTrailEvent.from_record({"userIdentity": {"type": "IAMUser", "userName": "alice"}})
    assert event.actor_name == "alice"
    assert event.is_root is False


def test_root_detection() -> None:
    event = CloudTrailEvent.from_record({"userIdentity": {"type": "Root"}})
    assert event.is_root is True


def test_assumed_role_actor_name_and_mfa() -> None:
    event = CloudTrailEvent.from_record(
        {
            "userIdentity": {
                "type": "AssumedRole",
                "sessionContext": {
                    "sessionIssuer": {"type": "Role", "userName": "DeployRole"},
                    "attributes": {"mfaAuthenticated": "true"},
                },
            }
        }
    )
    assert event.actor_name == "DeployRole"  # resolved via session issuer
    assert event.mfa_authenticated is True


def test_service_principal_via_invoked_by() -> None:
    event = CloudTrailEvent.from_record(
        {"userIdentity": {"type": "IAMUser", "invokedBy": "config.amazonaws.com"}}
    )
    assert event.is_service_principal is True


def test_service_principal_via_service_linked_role() -> None:
    event = CloudTrailEvent.from_record(
        {
            "userIdentity": {
                "type": "AssumedRole",
                "sessionContext": {
                    "sessionIssuer": {
                        "arn": "arn:aws:iam::111111111111:role/aws-service-role/"
                        "config.amazonaws.com/AWSServiceRoleForConfig"
                    }
                },
            }
        }
    )
    assert event.is_service_principal is True


def test_awsservice_type_is_service_principal() -> None:
    assert (
        CloudTrailEvent.from_record({"userIdentity": {"type": "AWSService"}}).is_service_principal
        is True
    )
