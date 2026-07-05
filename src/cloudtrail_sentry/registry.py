"""Rule registry and auto-discovery.

Rules register themselves with the :func:`register` decorator. :func:`discover`
imports every submodule of :mod:`cloudtrail_sentry.rules` so those decorators
run, and :func:`all_rules` returns a fresh, id-sorted instance of each. The
payoff: adding a rule means dropping one file in ``rules/`` — nothing here needs
to change.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable

from .rules.base import Rule

_REGISTRY: dict[str, type[Rule]] = {}
_discovered = False


def register(cls: type[Rule]) -> type[Rule]:
    """Class decorator that adds a :class:`Rule` subclass to the registry."""
    rule_id = getattr(cls, "id", None)
    if not rule_id:
        raise ValueError(f"{cls.__name__} must define a non-empty class-level `id`")
    existing = _REGISTRY.get(rule_id)
    if existing is not None and existing is not cls:
        raise ValueError(f"duplicate rule id {rule_id!r}: {cls.__name__} vs {existing.__name__}")
    _REGISTRY[rule_id] = cls
    return cls


def discover() -> None:
    """Import all rule submodules so their ``@register`` decorators execute."""
    global _discovered
    if _discovered:
        return
    from . import rules as rules_pkg

    for module in pkgutil.iter_modules(rules_pkg.__path__, rules_pkg.__name__ + "."):
        importlib.import_module(module.name)
    _discovered = True


def rule_classes() -> list[type[Rule]]:
    """Return every registered rule class, sorted by id."""
    discover()
    return [_REGISTRY[rule_id] for rule_id in sorted(_REGISTRY)]


def all_rules() -> list[Rule]:
    """Return a fresh instance of every registered rule, sorted by id."""
    return [cls() for cls in rule_classes()]


def known_rule_ids() -> set[str]:
    """Return the set of all registered rule ids."""
    return {cls.id for cls in rule_classes()}


def select_rules(
    *,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> list[Rule]:
    """Return rule instances filtered by an include and/or exclude id list.

    Ids are matched case-insensitively. ``include`` restricts to the given ids;
    ``exclude`` removes them. Applying both keeps included-but-not-excluded ids.
    """
    rules = all_rules()
    if include is not None:
        wanted = {rid.strip().upper() for rid in include}
        rules = [r for r in rules if r.id in wanted]
    if exclude is not None:
        unwanted = {rid.strip().upper() for rid in exclude}
        rules = [r for r in rules if r.id not in unwanted]
    return rules
