"""Small, defensive parsing helpers shared across the rule modules.

CloudTrail records are user-controlled JSON whose nested shapes vary by
``eventVersion`` and may contain ``null`` where an object is expected. Every
helper here fails soft (returns a default / empty result) rather than raising,
so a single odd record can never crash a scan.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import unquote


def dig(obj: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested mappings: ``dig(rec, "a", "b")`` -> ``rec["a"]["b"]``.

    Returns ``default`` if any level is missing or not a mapping.
    """
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def as_list(value: Any) -> list[Any]:
    """Normalize a scalar-or-list JSON value into a list.

    IAM policy fields such as ``Action`` and ``Statement`` may be a single
    value or an array; callers should not have to care which.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ec2_items(container: Any) -> list[dict[str, Any]]:
    """Return the ``items`` list from an EC2-style ``{"items": [...]}`` wrapper."""
    if not isinstance(container, dict):
        return []
    items = container.get("items")
    return items if isinstance(items, list) else []


def parse_policy_document(raw: Any) -> dict[str, Any] | None:
    """Decode an IAM policy document from a CloudTrail ``requestParameters`` value.

    In CloudTrail, ``policyDocument`` / ``bucketPolicy`` / ``policy`` are usually
    URL-encoded JSON strings, but are sometimes already-parsed objects. Handles
    both and returns ``None`` on anything unparseable.
    """
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    for candidate in (raw, unquote(raw)):
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def iter_statements(policy: dict[str, Any] | None) -> Iterator[dict[str, Any]]:
    """Yield each ``Statement`` object from a parsed IAM/resource policy."""
    if not isinstance(policy, dict):
        return
    for stmt in as_list(policy.get("Statement")):
        if isinstance(stmt, dict):
            yield stmt


def principal_is_wildcard(principal: Any) -> bool:
    """True if an IAM ``Principal`` grants access to everyone (``"*"``)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*" or (isinstance(value, list) and "*" in value):
                return True
    return False
