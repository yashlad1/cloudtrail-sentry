"""Tests for the defensive parsing helpers."""

from __future__ import annotations

import json
from urllib.parse import quote

from cloudtrail_sentry._util import (
    as_list,
    dig,
    ec2_items,
    iter_statements,
    parse_policy_document,
    principal_is_wildcard,
)


def test_dig_traverses_and_defaults() -> None:
    assert dig({"a": {"b": 1}}, "a", "b") == 1
    assert dig({"a": {"b": 1}}, "a", "missing", default="x") == "x"
    assert dig({"a": "scalar"}, "a", "b", default=None) is None
    assert dig(None, "a") is None


def test_as_list_normalizes() -> None:
    assert as_list(None) == []
    assert as_list("x") == ["x"]
    assert as_list(["x", "y"]) == ["x", "y"]


def test_ec2_items() -> None:
    assert ec2_items({"items": [{"a": 1}, {"b": 2}]}) == [{"a": 1}, {"b": 2}]
    assert ec2_items({}) == []
    assert ec2_items("not-a-dict") == []


def test_parse_policy_document_variants() -> None:
    doc = {"Version": "2012-10-17", "Statement": []}
    assert parse_policy_document(doc) == doc  # already an object
    assert parse_policy_document(json.dumps(doc)) == doc  # plain JSON string
    assert parse_policy_document(quote(json.dumps(doc))) == doc  # URL-encoded
    assert parse_policy_document(None) is None
    assert parse_policy_document(12345) is None
    assert parse_policy_document("{not json") is None


def test_iter_statements() -> None:
    single = {"Statement": {"Effect": "Allow"}}
    assert list(iter_statements(single)) == [{"Effect": "Allow"}]
    assert list(iter_statements(None)) == []
    assert list(iter_statements({"Statement": ["not-a-dict"]})) == []


def test_principal_is_wildcard() -> None:
    assert principal_is_wildcard("*") is True
    assert principal_is_wildcard({"AWS": "*"}) is True
    assert principal_is_wildcard({"AWS": ["arn:...", "*"]}) is True
    assert principal_is_wildcard({"AWS": "arn:aws:iam::111111111111:root"}) is False
    assert principal_is_wildcard({"Service": "s3.amazonaws.com"}) is False
