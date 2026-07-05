"""Data-driven tests over the on-disk fixtures.

Each ``events/<rule_id>.json`` must trigger the rule named by its filename;
each ``negatives/*.json`` must produce zero findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudtrail_sentry.engine import Engine
from cloudtrail_sentry.loader import iter_events
from cloudtrail_sentry.models import Finding

FIXTURES = Path(__file__).parent.parent / "fixtures"
EVENTS = sorted((FIXTURES / "events").glob("*.json"))
NEGATIVES = sorted((FIXTURES / "negatives").glob("*.json"))


def _scan(path: Path) -> list[Finding]:
    return Engine().run(iter_events([str(path)], warn=lambda _m: None))


@pytest.mark.parametrize("path", EVENTS, ids=lambda p: p.stem)
def test_positive_fixture_fires_its_rule(path: Path) -> None:
    expected_rule = path.stem.upper()
    fired = {finding.rule for finding in _scan(path)}
    assert expected_rule in fired, f"{path.name} did not fire {expected_rule}; got {fired}"


@pytest.mark.parametrize("path", NEGATIVES, ids=lambda p: p.stem)
def test_negative_fixture_is_clean(path: Path) -> None:
    assert _scan(path) == [], f"{path.name} unexpectedly produced findings"
