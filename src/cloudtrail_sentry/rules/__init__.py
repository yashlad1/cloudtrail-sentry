"""Detection rules.

Every module in this package is auto-imported by :func:`cloudtrail_sentry.registry.discover`,
so a new rule becomes active simply by defining a ``@register``-decorated
:class:`~cloudtrail_sentry.rules.base.Rule` subclass in a file here — there is no
central list to edit.
"""
