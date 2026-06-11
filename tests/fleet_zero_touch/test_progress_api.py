"""Progress API returns live, real stage state; the standalone page renders."""
from __future__ import annotations

from app.extensions import db

from tests.fleet_zero_touch.conftest import make_node, make_provider, set_full_infra


def _admin_login(client):
    from app.models import Admin
    a = Admin.query.first()
    if a is None:
        a = Admin(username="zt_test", active=True, is_super_admin=True)
        a.set_password("x" * 12)
        db.session.add(a)
        db.session.commit()
    with client.session_transaction() as sess:
        sess["admin_id"] = a.id
        sess["admin_name"] = a.full_name or a.username
        sess["_csrf_token"] = "zt-csrf"


_HDR = {"X-CSRFToken": "zt-csrf"}


def test_create_then_tick_returns_live_stages(app, client):
    set_full_infra()
    prov = make_provider()
    make_node(prov, "good", octet=11)
    db.session.commit()
    _admin_login(client)

    r = client.post("/admin/fleet/sync/jobs", json={"scope": "fleet"}, headers=_HDR)
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body["ok"] is True
    job = body["job"]
    job_id = job["id"]
    assert job["status"] in ("running", "done")
    # Eight named stages exist, all pending at creation.
    stages = job["nodes"][0]["stages"]
    assert [s["key"] for s in stages] == [
        "keys", "panel_peer", "proxy_peer", "script",
        "wg_mgmt", "wg_data", "routing", "radius",
    ]
    assert all(s["state"] == "pending" for s in stages)

    # Tick to completion via the polling endpoint.
    for _ in range(40):
        rt = client.post(f"/admin/fleet/sync/jobs/{job_id}/tick", headers=_HDR)
        assert rt.status_code == 200, rt.data
        j = rt.get_json()["job"]
        if j["status"] == "done":
            break
    assert j["status"] == "done"
    assert j["progress"]["percent"] == 100
    states = {s["key"]: s["state"] for s in j["nodes"][0]["stages"]}
    assert states["keys"] == "done"

    # GET json reflects the same terminal state.
    rg = client.get(f"/admin/fleet/sync/jobs/{job_id}.json", headers=_HDR)
    assert rg.status_code == 200
    assert rg.get_json()["job"]["status"] == "done"


def test_sync_page_renders(app, client):
    _admin_login(client)
    r = client.get("/admin/fleet/sync/", headers=_HDR)
    assert r.status_code == 200
    assert "إعادة مزامنة الأسطول".encode() in r.data
    assert b"fleet_sync_progress.js" in r.data


def test_create_requires_auth(app, client):
    r = client.post("/admin/fleet/sync/jobs", json={"scope": "fleet"})
    # login_required → redirect (302) or 401, never a 200 create.
    assert r.status_code in (301, 302, 401, 403)
