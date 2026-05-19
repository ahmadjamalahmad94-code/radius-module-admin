from __future__ import annotations


def test_health_endpoint_returns_ok(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.get_json()["ok"] is True


def test_license_check_requires_key_and_fingerprint(client):
    res = client.post("/api/license/check", json={"license_key": "HBR-2026-ABCD-EFGH-1234"})
    assert res.status_code == 422
    body = res.get_json()
    assert body["active"] is False
    assert body["mode"] == "denied"

