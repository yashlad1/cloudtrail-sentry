"""Meta-tests that enforce rule-catalog quality as the catalog grows."""

from __future__ import annotations

import re

import pytest

from cloudtrail_sentry.models import Severity
from cloudtrail_sentry.registry import (
    all_rules,
    known_rule_ids,
    register,
    rule_classes,
    select_rules,
)
from cloudtrail_sentry.rules.base import Rule

_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]+$")


def test_catalog_is_non_empty() -> None:
    assert len(rule_classes()) >= 14


@pytest.mark.parametrize("cls", rule_classes(), ids=lambda c: c.id)
def test_every_rule_is_well_formed(cls: type[Rule]) -> None:
    assert cls.id and _ID_PATTERN.match(cls.id), f"bad id: {cls.id!r}"
    assert cls.title.strip(), f"{cls.id} missing title"
    assert cls.remediation.strip(), f"{cls.id} missing remediation"
    assert isinstance(cls.severity, Severity)


def test_rule_ids_are_unique() -> None:
    ids = [cls.id for cls in rule_classes()]
    assert len(ids) == len(set(ids))


def test_all_rules_returns_fresh_instances() -> None:
    first = all_rules()
    second = all_rules()
    assert {r.id for r in first} == {r.id for r in second}
    # Fresh instances each call (so stateful correlation rules are safe).
    assert all(a is not b for a, b in zip(first, second, strict=True))


def test_known_rule_ids_matches_classes() -> None:
    assert known_rule_ids() == {cls.id for cls in rule_classes()}


def test_select_rules_include_and_exclude() -> None:
    only = select_rules(include=["security_group_open_to_internet"])
    assert [r.id for r in only] == ["SECURITY_GROUP_OPEN_TO_INTERNET"]

    without = select_rules(exclude=["SECURITY_GROUP_OPEN_TO_INTERNET"])
    assert "SECURITY_GROUP_OPEN_TO_INTERNET" not in {r.id for r in without}


def test_register_rejects_missing_id() -> None:
    with pytest.raises(ValueError, match="non-empty"):

        @register
        class _NoId(Rule):
            def evaluate(self, event):  # type: ignore[no-untyped-def]
                return ()


def test_register_rejects_duplicate_id() -> None:
    with pytest.raises(ValueError, match="duplicate"):

        @register
        class _Dup(Rule):
            id = "SECURITY_GROUP_OPEN_TO_INTERNET"
            title = "dup"
            severity = Severity.LOW
            remediation = "x"

            def evaluate(self, event):  # type: ignore[no-untyped-def]
                return ()
