"""Tests for the DB-first platform-settings resolver and its callers.

Coverage
========
* Precedence: DB row > app.config > built-in default.
* Type coercion: bool / int / enum / secret / str.
* Encryption: secrets stored as Fernet ciphertext, not plaintext.
* Form save: empty secret leaves the existing value alone (write-only);
  non-secrets save raw; bool with no form key clears to False.
* Caller integration: the rate-limit `check_rate_limit` hook honors a DB
  override of LOGIN_RATE_LIMIT_MAX without an app restart.
* Reset: clearing a Setting row falls back to config / default.
* Audit metadata never contains plaintext.
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Setting


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────

def _row(key: str) -> Setting | None:
    return db.session.get(Setting, key)


def _value(key: str) -> str:
    row = _row(key)
    return (row.value or "") if row else ""


# ────────────────────────────────────────────────────────────────────
# 1. Resolver precedence
# ────────────────────────────────────────────────────────────────────

def test_resolver_default_when_no_db_and_no_config(app):
    """When neither DB nor app.config has the value, the spec default wins."""
    from app.services import platform_settings as ps
    # WHATSAPP_DEFAULT_TIMEZONE has a real default; app.config also sets it.
    # Override the config to be empty so we exercise the default chain.
    app.config["WHATSAPP_DEFAULT_TIMEZONE"] = ""
    assert ps.get_str("WHATSAPP_DEFAULT_TIMEZONE") == "Asia/Hebron"


def test_resolver_falls_back_to_config(app):
    """No DB row, but app.config has it → resolver returns the config value."""
    from app.services import platform_settings as ps
    app.config["LOGIN_RATE_LIMIT_MAX"] = 25
    # No DB row
    assert _row("LOGIN_RATE_LIMIT_MAX") is None
    assert ps.get_int("LOGIN_RATE_LIMIT_MAX") == 25


def test_resolver_db_overrides_config(app):
    """DB row takes precedence over app.config (the whole point)."""
    from app.services import platform_settings as ps
    app.config["LOGIN_RATE_LIMIT_MAX"] = 99
    ps.set_value("LOGIN_RATE_LIMIT_MAX", 7)
    db.session.commit()
    assert ps.get_int("LOGIN_RATE_LIMIT_MAX") == 7


def test_resolver_empty_db_row_falls_back_to_config(app):
    """An empty Setting.value MUST fall back, not be treated as zero/blank."""
    from app.services import platform_settings as ps
    app.config["LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS"] = 444
    row = Setting(key="LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS", value="")
    db.session.add(row)
    db.session.commit()
    assert ps.get_int("LICENSE_CHECK_MAX_CLOCK_SKEW_SECONDS") == 444


# ────────────────────────────────────────────────────────────────────
# 2. Type coercion + validation
# ────────────────────────────────────────────────────────────────────

def test_bool_coercion_truthy(app):
    from app.services import platform_settings as ps
    for truthy in ["1", "true", "yes", "on", "y", "t"]:
        ps.set_value("RATE_LIMITS_ENABLED", truthy)
        db.session.commit()
        assert ps.get_bool("RATE_LIMITS_ENABLED") is True


def test_bool_coercion_falsy(app):
    from app.services import platform_settings as ps
    for falsy in ["0", "false", "no", "off", "n", "f"]:
        ps.set_value("RATE_LIMITS_ENABLED", falsy)
        db.session.commit()
        assert ps.get_bool("RATE_LIMITS_ENABLED") is False


def test_int_min_max_bounds(app):
    from app.services import platform_settings as ps
    with pytest.raises(ps.PlatformSettingsError):
        ps.set_value("LOGIN_RATE_LIMIT_MAX", 0)  # below min=1
    with pytest.raises(ps.PlatformSettingsError):
        ps.set_value("LOGIN_RATE_LIMIT_MAX", 999999)  # above max=10000


def test_enum_rejects_unknown_choice(app):
    from app.services import platform_settings as ps
    with pytest.raises(ps.PlatformSettingsError):
        ps.set_value("LOG_LEVEL", "TRACE")
    ps.set_value("LOG_LEVEL", "DEBUG")
    db.session.commit()
    assert ps.get_str("LOG_LEVEL") == "DEBUG"


def test_unknown_key_rejected(app):
    from app.services import platform_settings as ps
    with pytest.raises(ps.PlatformSettingsError):
        ps.set_value("DOES_NOT_EXIST", "anything")


# ────────────────────────────────────────────────────────────────────
# 3. Secret encryption + masking
# ────────────────────────────────────────────────────────────────────

def test_secret_stored_as_ciphertext(app):
    """The Setting.value must never contain the plaintext."""
    from app.services import platform_settings as ps
    plain = "very-long-shared-secret-1234567890"
    ps.set_value("RADIUS_PROXY_SHARED_SECRET", plain)
    db.session.commit()
    raw = _value("RADIUS_PROXY_SHARED_SECRET")
    assert raw != plain
    assert raw.startswith("gAAAA")  # Fernet token prefix
    # decrypted via the resolver
    assert ps.get_secret("RADIUS_PROXY_SHARED_SECRET") == plain


def test_secret_snapshot_never_returns_plaintext(app):
    from app.services import platform_settings as ps
    plain = "another-secret-1234567890ABCDEF"
    ps.set_value("LICENSE_CHECK_HMAC_SECRET", plain)
    db.session.commit()
    snap = ps.snapshot()
    # Find the SettingView for the HMAC secret across all groups
    found = None
    for views in snap.values():
        for v in views:
            if v.key == "LICENSE_CHECK_HMAC_SECRET":
                found = v
    assert found is not None
    assert found.value == ""           # never echo the plaintext
    assert plain not in found.masked   # masked form is safe
    assert "•" in found.masked or "…" in found.masked or "•" in found.masked


def test_secret_pending_owner_input_flag(app):
    """When the secret has no DB value and no env, snapshot flags it."""
    from app.services import platform_settings as ps
    app.config["RADIUS_PROXY_SHARED_SECRET"] = ""
    # Make sure no DB row either
    row = _row("RADIUS_PROXY_SHARED_SECRET")
    if row:
        db.session.delete(row)
        db.session.commit()
    snap = ps.snapshot()
    found = None
    for views in snap.values():
        for v in views:
            if v.key == "RADIUS_PROXY_SHARED_SECRET":
                found = v
    assert found is not None
    assert found.needs_owner_input is True


# ────────────────────────────────────────────────────────────────────
# 4. Form save — write-only secret semantics
# ────────────────────────────────────────────────────────────────────

def test_save_form_keeps_existing_secret_when_blank(app):
    """Empty secret submission must NOT blow away the stored ciphertext."""
    from app.services import platform_settings as ps
    plain = "keep-me-1234567890abcdef"
    ps.set_value("RADIUS_PROXY_SHARED_SECRET", plain)
    db.session.commit()
    pre = _value("RADIUS_PROXY_SHARED_SECRET")

    result = ps.save_form({
        # No "RADIUS_PROXY_SHARED_SECRET" key at all -> empty -> keep.
        "LOGIN_RATE_LIMIT_MAX": "42",
    })
    db.session.commit()
    post = _value("RADIUS_PROXY_SHARED_SECRET")
    assert post == pre  # unchanged
    assert ps.get_secret("RADIUS_PROXY_SHARED_SECRET") == plain
    assert "RADIUS_PROXY_SHARED_SECRET" not in result["secrets_rotated"]


def test_save_form_replaces_secret_when_supplied(app):
    from app.services import platform_settings as ps
    ps.save_form({"LICENSE_CHECK_HMAC_SECRET": "first-1234567890abcdefghij"})
    db.session.commit()
    assert ps.get_secret("LICENSE_CHECK_HMAC_SECRET") == "first-1234567890abcdefghij"

    result = ps.save_form({"LICENSE_CHECK_HMAC_SECRET": "second-abcdefghij1234567890"})
    db.session.commit()
    assert ps.get_secret("LICENSE_CHECK_HMAC_SECRET") == "second-abcdefghij1234567890"
    assert "LICENSE_CHECK_HMAC_SECRET" in result["secrets_rotated"]


def test_save_form_checkbox_semantics_for_booleans(app):
    """Boolean toggles: missing form key == unchecked == False."""
    from app.services import platform_settings as ps
    # Start truthy
    ps.set_value("RATE_LIMITS_ENABLED", "1")
    db.session.commit()
    assert ps.get_bool("RATE_LIMITS_ENABLED") is True
    # Submit a form WITHOUT the checkbox key -> off
    ps.save_form({"LOGIN_RATE_LIMIT_MAX": "5"})
    db.session.commit()
    assert ps.get_bool("RATE_LIMITS_ENABLED") is False


def test_save_form_audit_metadata_never_contains_plaintext(app):
    """The audit hook gets booleans only — never the secret string."""
    from app.services import platform_settings as ps
    captured: list = []

    def fake_audit(action, etype, eid, summary, metadata=None):
        captured.append({"action": action, "metadata": metadata})

    plain = "secret-never-in-audit-XYZ1234567890"
    ps.save_form(
        {"LICENSE_CHECK_HMAC_SECRET": plain, "LOGIN_RATE_LIMIT_MAX": "11"},
        actor_audit=fake_audit,
    )
    assert captured
    md = captured[0]["metadata"]
    assert md["secrets_rotated"] == ["LICENSE_CHECK_HMAC_SECRET"]
    # Nothing in metadata should equal the plaintext or contain it.
    import json
    assert plain not in json.dumps(md, ensure_ascii=False)


# ────────────────────────────────────────────────────────────────────
# 5. Caller integration — the rate-limit hook honors the DB value live
# ────────────────────────────────────────────────────────────────────

def test_rate_limit_check_uses_db_override(app, client):
    """If the operator drops LOGIN_RATE_LIMIT_MAX to 1 via the UI, the 2nd
    login attempt within the window should be 429 — no restart required."""
    from app.services import platform_settings as ps
    ps.set_value("RATE_LIMITS_ENABLED", "1")
    ps.set_value("LOGIN_RATE_LIMIT_MAX", "1")
    ps.set_value("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "60")
    db.session.commit()

    # We don't need a real admin row — login_post is the rate-limited endpoint.
    # First hit consumes the budget; the second one should be 429.
    r1 = client.post("/login", data={"username": "x", "password": "x"})
    assert r1.status_code in (200, 401)  # rate-limit not yet tripped
    r2 = client.post("/login", data={"username": "x", "password": "x"})
    assert r2.status_code == 429
    assert "Retry-After" in r2.headers


def test_rate_limit_disabled_via_db(app, client):
    """Toggling RATE_LIMITS_ENABLED=0 should silence the limiter."""
    from app.services import platform_settings as ps
    ps.set_value("RATE_LIMITS_ENABLED", "0")
    ps.set_value("LOGIN_RATE_LIMIT_MAX", "1")  # would normally trip
    ps.set_value("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "60")
    db.session.commit()
    for _ in range(5):
        r = client.post("/login", data={"username": "x", "password": "x"})
        assert r.status_code != 429


# ────────────────────────────────────────────────────────────────────
# 6. Reset — clearing the DB row falls back to config / default
# ────────────────────────────────────────────────────────────────────

def test_reset_falls_back_to_config(app):
    from app.services import platform_settings as ps
    app.config["LOGIN_RATE_LIMIT_MAX"] = 33
    ps.set_value("LOGIN_RATE_LIMIT_MAX", 7)
    db.session.commit()
    assert ps.get_int("LOGIN_RATE_LIMIT_MAX") == 7

    # Mimic the route's reset: clear the row's value.
    row = _row("LOGIN_RATE_LIMIT_MAX")
    row.value = ""
    db.session.add(row)
    db.session.commit()
    # The route invalidates the per-request cache; replicate that here since
    # we bypassed set_value() to simulate the reset endpoint's behavior.
    ps._invalidate_cache()
    assert ps.get_int("LOGIN_RATE_LIMIT_MAX") == 33  # config fallback


# ────────────────────────────────────────────────────────────────────
# 7. UI snapshot health
# ────────────────────────────────────────────────────────────────────

def test_health_counts(app):
    from app.services import platform_settings as ps
    initial = ps.health()
    assert initial["total"] == len(ps.KEYS)
    assert initial["with_db_override"] == 0

    ps.set_value("LOG_LEVEL", "DEBUG")
    db.session.commit()
    later = ps.health()
    assert later["with_db_override"] == 1
