"""POST /api/proxy/heartbeat ingests `proxy_wg_data_pubkey` (BUG B - proxy side).

Companion to fix/fleet-wireguard-provisioning. The CHR script's
``PROXY_WG_PUBKEY`` is sourced from
``Setting fleet.infra.PROXY_WG_PUBKEY``. Without this ingest path, a
rotated key on the proxy host leaves every NEW CHR script trusting a
stale key — the same failure mode chr-vpn-1/2 hit on the panel side
(BUG B). The proxy's heartbeat carries the LIVE wg-data pubkey under
``proxy_wg_data_pubkey``; the panel adopts it when it differs.

Acceptance:

  1. Heartbeat with a fresh non-empty 44-char key → Setting updated +
     audit row appended.
  2. Heartbeat with the SAME key → no-op (no audit on the hot path).
  3. Heartbeat with ``""`` / missing → Setting unchanged (proxy
     unprivileged / iface absent; no signal).
  4. Heartbeat with an invalid key (wrong length / not base64-44) →
     Setting unchanged + warning logged + no audit.
  5. The heartbeat still returns 200 even when adoption logic raises
     internally (defence in depth via the route-level try/except).
"""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.extensions import db
from app.models import AuditLog


SHARED_SECRET = "test-heartbeat-ingest-secret"
URL = "/api/proxy/heartbeat"


@pytest.fixture()
def proxy_app(app):
    app.config["RADIUS_PROXY_SHARED_SECRET"] = SHARED_SECRET
    app.config["RADIUS_PROXY_TOKEN_TTL"] = 60
    from app.api import proxy_api
    proxy_api._NONCE_CACHE.clear()
    return app


_NONCE_SEQ = [0]


def _token() -> str:
    _NONCE_SEQ[0] += 1
    ts = int(time.time())
    nonce = f"hb-ingest-{ts}-{_NONCE_SEQ[0]}"
    mac = hmac.new(SHARED_SECRET.encode(), f"{ts}:{nonce}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{ts}:{nonce}:{mac}"


def _stored_proxy_pubkey() -> str:
    from fleet.registry.infra_settings import get_fleet_const
    return (get_fleet_const("PROXY_WG_PUBKEY") or "").strip()


def _audit_count() -> int:
    return AuditLog.query.filter_by(
        action="fleet_infra_proxy_pubkey_auto_adopted"
    ).count()


# ════════════════════════════════════════════════════════════════════════
# 1. The headline adoption
# ════════════════════════════════════════════════════════════════════════


def test_adopts_new_valid_pubkey_when_setting_unset(proxy_app, client):
    """Clean install: no PROXY_WG_PUBKEY stored → adopt the heartbeat's
    value and emit an audit row carrying old=<unset> / new=<key>."""
    assert _stored_proxy_pubkey() == ""
    new_key = "A" * 43 + "="
    r = client.post(URL,
                    headers={"X-Proxy-Token": _token()},
                    json={"proxy_id": "proxy-01",
                          "proxy_wg_data_pubkey": new_key})
    assert r.status_code == 200, r.data
    assert _stored_proxy_pubkey() == new_key
    rows = AuditLog.query.filter_by(
        action="fleet_infra_proxy_pubkey_auto_adopted").all()
    assert len(rows) == 1
    row = rows[0]
    assert row.entity_type == "fleet_infra"
    assert row.entity_id == "PROXY_WG_PUBKEY"
    assert new_key in (row.summary or "")
    meta = row.meta or {}
    assert meta.get("source") == "proxy_heartbeat"
    assert meta.get("proxy_id") == "proxy-01"
    assert meta.get("old_pubkey") == ""
    assert meta.get("new_pubkey") == new_key


def test_adopts_rotated_pubkey_and_records_old_value(proxy_app, client):
    """Rotation case: stored != heartbeat → adopt + audit with the
    OLD pubkey in the metadata so the operator can see what changed."""
    from fleet.registry.infra_settings import set_proxy_pubkey
    old_key = "B" * 43 + "="
    new_key = "C" * 43 + "="
    set_proxy_pubkey(old_key)
    assert _stored_proxy_pubkey() == old_key

    r = client.post(URL,
                    headers={"X-Proxy-Token": _token()},
                    json={"proxy_id": "proxy-01",
                          "proxy_wg_data_pubkey": new_key})
    assert r.status_code == 200
    assert _stored_proxy_pubkey() == new_key
    rows = AuditLog.query.filter_by(
        action="fleet_infra_proxy_pubkey_auto_adopted").all()
    assert len(rows) == 1
    assert (rows[0].meta or {}).get("old_pubkey") == old_key
    assert (rows[0].meta or {}).get("new_pubkey") == new_key


# ════════════════════════════════════════════════════════════════════════
# 2. Idempotency
# ════════════════════════════════════════════════════════════════════════


def test_same_key_is_a_noop(proxy_app, client):
    """Hot-path idempotency: a heartbeat that carries the SAME key the
    panel already has must NOT emit an audit row or re-write the
    Setting (no churn on every poll)."""
    from fleet.registry.infra_settings import set_proxy_pubkey
    key = "D" * 43 + "="
    set_proxy_pubkey(key)
    # Two heartbeats with the same key → still ZERO audit rows.
    for _ in range(2):
        r = client.post(URL,
                        headers={"X-Proxy-Token": _token()},
                        json={"proxy_id": "proxy-01",
                              "proxy_wg_data_pubkey": key})
        assert r.status_code == 200
    assert _stored_proxy_pubkey() == key
    assert _audit_count() == 0


# ════════════════════════════════════════════════════════════════════════
# 3. Empty / missing → no signal
# ════════════════════════════════════════════════════════════════════════


def test_empty_pubkey_is_ignored(proxy_app, client):
    """Empty string = proxy unprivileged / iface absent → KEEP stored."""
    from fleet.registry.infra_settings import set_proxy_pubkey
    key = "E" * 43 + "="
    set_proxy_pubkey(key)
    r = client.post(URL,
                    headers={"X-Proxy-Token": _token()},
                    json={"proxy_id": "proxy-01",
                          "proxy_wg_data_pubkey": ""})
    assert r.status_code == 200
    assert _stored_proxy_pubkey() == key
    assert _audit_count() == 0


def test_missing_pubkey_is_ignored(proxy_app, client):
    """Missing field (older proxy) → KEEP stored, no audit."""
    from fleet.registry.infra_settings import set_proxy_pubkey
    key = "F" * 43 + "="
    set_proxy_pubkey(key)
    r = client.post(URL,
                    headers={"X-Proxy-Token": _token()},
                    json={"proxy_id": "proxy-01"})
    assert r.status_code == 200
    assert _stored_proxy_pubkey() == key
    assert _audit_count() == 0


# ════════════════════════════════════════════════════════════════════════
# 4. Invalid input → reject + keep stored
# ════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("bad_value", [
    "too-short",                    # not 44 chars
    "G" * 44,                       # no trailing '='
    "G" * 43 + "*",                 # not base64
    "G" * 45 + "=",                 # too long
    " " * 44,                       # whitespace only
    "G" * 42 + "=",                 # 43 chars
])
def test_invalid_pubkey_is_rejected(proxy_app, client, bad_value):
    """Anything that wouldn't pass the manual UI validator must NOT be
    adopted from a heartbeat either. The Setting stays as-is, no audit."""
    from fleet.registry.infra_settings import set_proxy_pubkey
    key = "H" * 43 + "="
    set_proxy_pubkey(key)
    r = client.post(URL,
                    headers={"X-Proxy-Token": _token()},
                    json={"proxy_id": "proxy-01",
                          "proxy_wg_data_pubkey": bad_value})
    assert r.status_code == 200, r.data
    assert _stored_proxy_pubkey() == key, (
        f"adoption mistakenly accepted invalid value {bad_value!r}"
    )
    assert _audit_count() == 0


# ════════════════════════════════════════════════════════════════════════
# 5. Defence in depth — adoption never crashes the heartbeat ack
# ════════════════════════════════════════════════════════════════════════


def test_adoption_raising_does_not_break_heartbeat(proxy_app, client, monkeypatch):
    """If the underlying setter throws (e.g. transient DB failure), the
    heartbeat must still ack with 200 so the proxy keeps polling and the
    routing table stays fresh. Adoption failure logs but never breaks."""
    from app.api import proxy_api

    def _boom(body):
        raise RuntimeError("simulated adoption failure")
    monkeypatch.setattr(
        proxy_api, "_adopt_proxy_wg_pubkey_from_heartbeat", _boom,
    )
    r = client.post(URL,
                    headers={"X-Proxy-Token": _token()},
                    json={"proxy_id": "proxy-01",
                          "proxy_wg_data_pubkey": "I" * 43 + "="})
    assert r.status_code == 200, (
        "heartbeat must ack 200 even when adoption raises -- the proxy "
        "needs to keep polling regardless of a panel-side bug"
    )


# ════════════════════════════════════════════════════════════════════════
# 6. Contract presence — the field name is in the docstring
# ════════════════════════════════════════════════════════════════════════


def test_contract_documents_field_in_docstring():
    """The heartbeat handler's docstring must name the field so a future
    proxy-team consumer can grep `proxy_wg_data_pubkey` and find the
    panel contract."""
    from app.api.proxy_api import heartbeat
    doc = heartbeat.__doc__ or ""
    assert "proxy_wg_data_pubkey" in doc, (
        "heartbeat docstring must name the field so its semantics are "
        "discoverable from the source"
    )
