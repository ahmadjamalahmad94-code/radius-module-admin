"""Per-customer accel-ppp install bundle endpoint (2c) — curl|tar, no GitHub/scp.

The owner installs on his EXISTING VPS with one `curl … | tar` + a run command
that carries only the SECRETS; SUBDOMAIN/VPS_IP/dns01 are pre-filled. The bundle
endpoint is token-gated (the VPS fetches it unauthenticated) and contains no
secrets.
"""
from __future__ import annotations

import io
import tarfile

import pytest

from app.extensions import db
from app.models import Admin, Customer


def _customer(vps_ip="187.77.70.18"):
    c = Customer(company_name="VPS Co", email="vps@example.com", status="active", vps_ip=vps_ip)
    db.session.add(c)
    db.session.commit()
    return c


def _members(data: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            f = tar.extractfile(m)
            out[m.name] = f.read() if f else b""
    return out


# ── token ─────────────────────────────────────────────────────────────────────
def test_bundle_token_roundtrip_and_tamper(app):
    with app.app_context():
        from app.services.data_connection_bundle import bundle_token, verify_bundle_token
        t = bundle_token(42)
        assert verify_bundle_token(t) == 42
        assert verify_bundle_token(t + "x") is None      # tampered
        assert verify_bundle_token("") is None
        assert verify_bundle_token("not-a-token") is None


# ── bundle contents ─────────────────────────────────────────────────────────--
def test_bundle_contains_all_files_and_prefilled_script(app):
    with app.app_context():
        from app.services.data_connection_bundle import build_bundle_targz
        c = _customer()
        data = build_bundle_targz(c)
        members = _members(data)
        assert "accel-ppp/setup-radius-vps.sh" in members
        assert "accel-ppp/accel-ppp.conf.tmpl" in members
        assert "accel-ppp/agent/vps_agent.py" in members
        assert "accel-ppp/agent/__init__.py" in members
        script = members["accel-ppp/setup-radius-vps.sh"].decode("utf-8")
        # SUBDOMAIN + VPS_IP + dns01 pre-filled as the script defaults
        assert f'SUBDOMAIN="${{SUBDOMAIN:-client{c.id}.hoberadius.com}}"' in script
        assert 'VPS_IP="${VPS_IP:-187.77.70.18}"' in script
        assert 'CERT_CHALLENGE="${CERT_CHALLENGE:-dns01}"' in script
        # NO secret is ever baked into the downloadable bundle
        assert "RADIUS_SECRET=" in script  # the var line exists…
        assert 'RADIUS_SECRET="${RADIUS_SECRET:-}"' in script  # …but stays empty


def test_bundle_is_deterministic(app):
    with app.app_context():
        from app.services.data_connection_bundle import build_bundle_targz
        c = _customer()
        assert build_bundle_targz(c) == build_bundle_targz(c)


# ── endpoint gating ─────────────────────────────────────────────────────────--
def test_endpoint_requires_valid_token_when_anonymous(app, client):
    with app.app_context():
        c = _customer()
        cid = c.id
        from app.services.data_connection_bundle import bundle_token
        good = bundle_token(cid)
    # no token → 403
    assert client.get(f"/admin/customers/{cid}/data-bundle.tar.gz").status_code == 403
    # wrong-customer token → 403
    with app.app_context():
        from app.services.data_connection_bundle import bundle_token
        wrong = bundle_token(cid + 999)
    assert client.get(f"/admin/customers/{cid}/data-bundle.tar.gz?t={wrong}").status_code == 403
    # valid token → 200 gzip
    r = client.get(f"/admin/customers/{cid}/data-bundle.tar.gz?t={good}")
    assert r.status_code == 200
    assert r.mimetype == "application/gzip"
    assert _members(r.data)["accel-ppp/setup-radius-vps.sh"]  # decodes


def test_endpoint_allows_logged_in_admin_without_token(app, client):
    with app.app_context():
        c = _customer()
        cid = c.id
        a = Admin.query.first()
        aid = a.id
    with client.session_transaction() as s:
        s["admin_id"] = aid
    r = client.get(f"/admin/customers/{cid}/data-bundle.tar.gz")
    assert r.status_code == 200
    assert r.mimetype == "application/gzip"


# ── committed source still defaults to `auto` (only the SERVED copy is dns01) ──
def test_committed_script_default_challenge_unchanged(app):
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    s = (root / "deploy" / "accel-ppp" / "setup-radius-vps.sh").read_text(encoding="utf-8")
    assert 'CERT_CHALLENGE="${CERT_CHALLENGE:-auto}"' in s   # source default is auto
