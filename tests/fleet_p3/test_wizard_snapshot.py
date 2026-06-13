"""Render the add-CHR wizard end-to-end through Flask's test client and
save the HTML to repo root so the owner can open it in any browser to
verify the credential prompt is gone."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.extensions import db
from app.models import Admin
from fleet.registry.models_chr import FleetProvider


@pytest.fixture()
def provider_app(app):
    p = FleetProvider(name="contabo-de", cost_model="open", price_per_tb=0)
    db.session.add(p); db.session.commit()
    return app


def test_wizard_snapshot_no_credential_prompt(provider_app, client):
    client.post("/login", data={"username": "admin", "password": "admin12345"})
    adm = Admin.query.first()
    if adm and not adm.is_super_admin:
        adm.is_super_admin = True
        db.session.commit()

    resp = client.get("/admin/fleet/onboarding/new")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Pin every invariant the owner cares about ONCE, in the snapshot
    # test itself, so a regression that re-introduces the prompt fails
    # both this and the dedicated unit test.
    assert 'name="bootstrap_endpoint"' not in body
    assert 'name="bootstrap_user"' not in body
    assert 'name="bootstrap_pass"' not in body
    assert "اعتمادات الإدارة تلقائية" in body
    assert "hobe-panel" in body
    assert "hobe-fleet-mgmt" in body

    out = Path(__file__).resolve().parents[2] / "_wizard_no_creds_snapshot.html"
    out.write_text(body, encoding="utf-8")
