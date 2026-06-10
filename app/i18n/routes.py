"""Tiny endpoint that swaps the active UI language.

The switcher in the top bar POSTs here with ``locale=<code>``; we update
the session and bounce back to the originating page. Public — no
``login_required`` because the login page itself ships the switcher.
"""
from __future__ import annotations

from urllib.parse import urlparse

from flask import Blueprint, redirect, request, url_for

from . import SUPPORTED_LOCALES, set_locale

bp = Blueprint("i18n", __name__, url_prefix="/i18n")


def _safe_next(target: str | None) -> str:
    """Same-origin relative redirect targets only — anti-open-redirect."""
    target = (target or "").strip()
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        # External URL — refuse.
        return "/"
    return target if target.startswith("/") else "/"


@bp.post("/set")
def set_locale_route():
    code = (request.form.get("locale") or "").strip().lower()
    if code not in SUPPORTED_LOCALES:
        return redirect(_safe_next(request.referrer))
    set_locale(code)
    return redirect(_safe_next(request.form.get("next") or request.referrer))
