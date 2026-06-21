"""Admin-configurable thresholds for the countdown/depletion engine.

Stored in the existing ``settings`` table (key/value) so they're editable
without a migration. Sane defaults match the spec: 7/3/1 days before expiry,
and 100/50 remaining messages.
"""
from __future__ import annotations

import json
from typing import Iterable

from app.extensions import db
from app.models import Setting

_EXPIRY_KEY = "notifications.expiry_threshold_days"
_PACKAGE_KEY = "notifications.package_remaining_thresholds"

DEFAULT_EXPIRY_DAYS = [7, 3, 1]
DEFAULT_PACKAGE_REMAINING = [100, 50]


def _get_int_list(key: str, default: list[int]) -> list[int]:
    row = db.session.get(Setting, key)
    if row is None or not (row.value or "").strip():
        return list(default)
    try:
        raw = json.loads(row.value)
        vals = sorted({int(v) for v in raw if int(v) > 0}, reverse=True)
        return vals or list(default)
    except (ValueError, TypeError):
        return list(default)


def _set_int_list(key: str, values: Iterable[int]) -> list[int]:
    vals = sorted({int(v) for v in values if int(v) > 0}, reverse=True)
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=json.dumps(vals))
        db.session.add(row)
    else:
        row.value = json.dumps(vals)
    return vals


def expiry_thresholds() -> list[int]:
    """Days-before-expiry at which to alert (e.g. [7, 3, 1]). On-expiry (0)
    is always emitted in addition to these."""
    return _get_int_list(_EXPIRY_KEY, DEFAULT_EXPIRY_DAYS)


def package_thresholds() -> list[int]:
    """Remaining-messages levels at which to alert (e.g. [100, 50]). Empty (0)
    is always emitted in addition to these."""
    return _get_int_list(_PACKAGE_KEY, DEFAULT_PACKAGE_REMAINING)


def set_expiry_thresholds(values: Iterable[int]) -> list[int]:
    return _set_int_list(_EXPIRY_KEY, values)


def set_package_thresholds(values: Iterable[int]) -> list[int]:
    return _set_int_list(_PACKAGE_KEY, values)
