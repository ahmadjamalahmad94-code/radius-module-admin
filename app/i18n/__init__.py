"""Tiny gettext-shaped i18n layer for the admin panel.

The whole UI is authored in Arabic; ``_(key)`` returns the matching string
for the current request's locale, or the key itself when no translation
exists. The KEY is the Arabic source text — same convention Flask-Babel
uses with ``gettext("الإعدادات")``. That keeps the templates readable
even when a locale catalog is incomplete.

Why a hand-rolled layer instead of Flask-Babel's ``.po`` pipeline?

* Catalogs live as plain JSON files under ``app/i18n/locales/<code>.json``.
  No ``pybabel extract`` / ``pybabel compile`` step in CI; the owner can
  edit a locale file and reload the app.
* Missing keys fall back to the Arabic source automatically — perfect
  for the scaffolded French / Turkish locales the spec ships with.
* The runtime contract still mimics gettext: a Jinja global ``_`` and
  ``gettext``, plus ``ngettext`` for plurals. If we later switch to
  Flask-Babel we just point its catalog at the JSON files.

Public surface:

* :func:`gettext(key)` — translate ONE key for the active locale.
* :func:`ngettext(singular, plural, n)` — plural form (rudimentary; falls
  back to ``singular`` for n==1 and ``plural`` otherwise).
* :func:`current_locale()` — the active locale code (e.g. ``"ar"``).
* :func:`current_dir()` — ``"rtl"`` for Arabic, ``"ltr"`` otherwise.
* :func:`set_locale(code)` — switch the session's locale (used by the
  switcher route).
* :func:`init_app(app)` — wire the Jinja globals + request context
  processor onto the Flask app.

The set of supported locales lives in :data:`SUPPORTED_LOCALES`.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from flask import Flask, g, request, session

_log = logging.getLogger(__name__)


SUPPORTED_LOCALES: dict[str, dict[str, Any]] = {
    "ar": {"label": "العربية",   "english_name": "Arabic",  "dir": "rtl", "flag": "🇸🇦"},
    "en": {"label": "English",   "english_name": "English", "dir": "ltr", "flag": "🇬🇧"},
    "fr": {"label": "Français",  "english_name": "French",  "dir": "ltr", "flag": "🇫🇷"},
    "tr": {"label": "Türkçe",    "english_name": "Turkish", "dir": "ltr", "flag": "🇹🇷"},
}

DEFAULT_LOCALE = "ar"
SESSION_KEY = "_locale"

_LOCALES_DIR = Path(__file__).resolve().parent / "locales"


# ── catalog loading ──────────────────────────────────────────────────────

def _load_catalog(code: str) -> dict[str, str]:
    """Read one ``<code>.json`` from disk.

    Returns ``{}`` for an unknown / unreadable locale. The Arabic catalog is
    intentionally minimal: ``ar`` IS the source, so its file just contains
    the few keys that need a long-form rewrite (e.g. plural-aware labels).
    """
    path = _LOCALES_DIR / f"{code}.json"
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        _log.warning("i18n: cannot read %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _catalogs() -> dict[str, dict[str, str]]:
    """Lazy in-process cache. Reloaded in DEBUG so the owner can edit a
    JSON file and refresh the page without restarting the dev server."""
    cache: dict[str, dict[str, str]] | None = getattr(_catalogs, "_cache", None)
    if cache is None or os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true"}:
        cache = {code: _load_catalog(code) for code in SUPPORTED_LOCALES}
        _catalogs._cache = cache  # type: ignore[attr-defined]
    return cache


# ── locale resolution ────────────────────────────────────────────────────

def current_locale() -> str:
    """Return the active locale for this request.

    Resolution order (first hit wins):
    1. ``g._locale`` if set by a per-request helper.
    2. ``session["_locale"]`` if the admin picked one via the switcher.
    3. ``?lang=xx`` query string (handy for previews / screenshots).
    4. Best-match from ``Accept-Language``.
    5. :data:`DEFAULT_LOCALE`.
    """
    cached = getattr(g, "_locale", None) if request else None
    if cached:
        return cached
    if request is not None:
        chosen = session.get(SESSION_KEY) if session else None
        if chosen in SUPPORTED_LOCALES:
            g._locale = chosen
            return chosen
        qs = request.args.get("lang") if request else None
        if qs and qs in SUPPORTED_LOCALES:
            g._locale = qs
            return qs
        accept = (request.headers.get("Accept-Language") or "").lower() if request else ""
        for fragment in accept.split(","):
            code = fragment.split(";", 1)[0].strip().split("-", 1)[0]
            if code in SUPPORTED_LOCALES:
                g._locale = code
                return code
    return DEFAULT_LOCALE


def current_dir() -> str:
    return SUPPORTED_LOCALES.get(current_locale(), {}).get("dir", "ltr")


def set_locale(code: str) -> str:
    """Persist a locale choice on the session. Caller commits the session
    via the normal Flask response cycle."""
    if code not in SUPPORTED_LOCALES:
        code = DEFAULT_LOCALE
    session[SESSION_KEY] = code
    g._locale = code
    return code


# ── translation primitives ───────────────────────────────────────────────

def gettext(key: str, **fmt: Any) -> str:
    """Return the translation for ``key`` in the current locale.

    If the locale catalog is missing the key, fall back to ``key`` itself
    (which IS the Arabic source). ``fmt`` runs ``str.format`` on the final
    string so callers can pass ``_("...", count=3)`` for parameterised
    messages.
    """
    if not key:
        return ""
    code = current_locale()
    if code != DEFAULT_LOCALE:
        catalog = _catalogs().get(code, {})
        text = catalog.get(key)
        if text:
            return text.format(**fmt) if fmt else text
    # AR base (or unknown locale): use the key, optionally formatted.
    return key.format(**fmt) if fmt else key


# Gettext-compatible alias so existing tooling/IDEs that lint ``_(...)``
# calls treat this as an i18n call site.
_ = gettext


def ngettext(singular: str, plural: str, n: int, **fmt: Any) -> str:
    """Pluralised gettext.

    The current implementation uses a binary singular/plural split — enough
    for English and Arabic's most common forms. Languages with richer
    plurals (Russian, Polish) would need a CLDR plural-rule lookup; out of
    scope for the initial scaffolding.
    """
    key = singular if n == 1 else plural
    return gettext(key, n=n, **fmt) if fmt else gettext(key)


# ── coverage diagnostics (used by the locale picker page) ────────────────

def catalog_stats() -> list[dict[str, Any]]:
    """Per-locale coverage summary for the settings UI / docs."""
    base_size = len(_catalogs().get("en", {}))  # EN is the most complete non-base
    out: list[dict[str, Any]] = []
    for code, meta in SUPPORTED_LOCALES.items():
        size = len(_catalogs().get(code, {}))
        out.append({
            "code": code,
            "label": meta["label"],
            "english_name": meta["english_name"],
            "dir": meta["dir"],
            "flag": meta["flag"],
            "keys": size,
            "pct": (round(100 * size / base_size) if base_size and code != "ar" else (100 if code == "ar" else 0)),
            "is_base": code == DEFAULT_LOCALE,
        })
    return out


# ── Flask wiring ─────────────────────────────────────────────────────────

def init_app(app: Flask) -> None:
    """Wire i18n onto the Flask app.

    * ``_`` / ``gettext`` / ``ngettext`` exposed as Jinja globals
    * ``locale`` / ``current_dir`` exposed as template context
    * Cache flushed on app startup so the first request reads fresh catalogs
    """
    _catalogs()  # warm cache; surfaces JSON errors at boot rather than on first render

    app.jinja_env.globals.update({
        "_": gettext,
        "gettext": gettext,
        "ngettext": ngettext,
    })

    @app.context_processor
    def _inject_locale() -> dict[str, Any]:
        return {
            "current_locale": current_locale(),
            "current_dir": current_dir(),
            "supported_locales": SUPPORTED_LOCALES,
        }


__all__ = [
    "DEFAULT_LOCALE",
    "SUPPORTED_LOCALES",
    "catalog_stats",
    "current_dir",
    "current_locale",
    "gettext",
    "init_app",
    "ngettext",
    "set_locale",
]
