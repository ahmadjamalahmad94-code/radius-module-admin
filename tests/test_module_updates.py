"""Per-customer OPT-IN self-update feed — provider publish + signed endpoint.

Covers:
  • publishing a version makes GET /api/integration/hoberadius/update/latest
    return it (HTTPS + license-resolution guarded);
  • an unpublished/empty state returns {"version": null};
  • the Arabic changelog markdown round-trips byte-for-byte;
  • per-customer targeting never leaks another customer's release;
  • "latest" is highest semver (1.10.0 > 1.9.0), not string/date order;
  • the guard rejects an unknown license and requires HTTPS;
  • the admin publish UI creates a release the endpoint then serves.
"""
from __future__ import annotations

import time
from datetime import timedelta

from app.extensions import db
from app.models import Admin, Customer, License, ModuleRelease, Plan, utcnow
from app.services.license_service import generate_license_key

HTTPS = "https://license-panel.test"
UPDATE_URL = "/api/integration/hoberadius/update/latest"


def _customer_with_license(name="Update Co", key=None):
    plan = Plan.query.filter_by(slug="pro").one()
    now = utcnow()
    customer = Customer(company_name=name, email=f"{name.replace(' ', '')}@ex.com", status="active")
    db.session.add(customer)
    db.session.flush()
    lic = License(
        customer_id=customer.id, plan_id=plan.id,
        license_key=key or generate_license_key(), status="active",
        starts_at=now - timedelta(days=1), expires_at=now + timedelta(days=30),
        grace_until=now + timedelta(days=37), max_fingerprints=3,
    )
    db.session.add(lic)
    db.session.commit()
    return customer, lic


def _envelope(license_key, *, nonce="n1", version="1.0.0"):
    # Bearer mode: the license_key IS the credential; a signature field is
    # accepted but not cryptographically required (see verify_license_signature).
    return {
        "license_key": license_key,
        "server_fingerprint": f"fp-{nonce}",
        "hostname": "radius-runtime",
        "version": version,
        "timestamp": int(time.time()),
        "nonce": nonce,
        "signature": "x",
    }


def _login_super(client):
    admin = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = admin.id
        s["is_super_admin"] = True
    return client


# ── endpoint returns a published release ─────────────────────────────────────
def test_update_latest_returns_published_release(client):
    from app.services import module_updates as mu
    customer, lic = _customer_with_license()
    mu.publish_release(version="1.4.2", changelog_md="## جديد\n- تحسينات",
                       mandatory=True, min_version="1.0.0")
    db.session.commit()

    res = client.get(UPDATE_URL, json=_envelope(lic.license_key), base_url=HTTPS)
    assert res.status_code == 200
    body = res.get_json()
    assert body["version"] == "1.4.2"
    assert body["mandatory"] is True
    assert body["min_version"] == "1.0.0"
    assert body["changelog_md"] == "## جديد\n- تحسينات"
    assert body["released_at"] and body["released_at"].endswith("Z")


# ── POST with the signed body returns the feed (not 405) ─────────────────────
def test_update_latest_accepts_post_body(client):
    """The radius side POSTs the signed envelope as the body (reverse proxies
    strip GET bodies). The endpoint must accept POST, not answer 405."""
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    mu.publish_release(version="2.1.0", changelog_md="via post", min_version="2.0.0")
    db.session.commit()

    res = client.post(UPDATE_URL, json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS)
    assert res.status_code == 200            # not 405 Method Not Allowed
    body = res.get_json()
    assert body["version"] == "2.1.0"
    assert body["min_version"] == "2.0.0"
    assert body["changelog_md"] == "via post"

    # GET keeps working identically (both methods share the handler).
    res_get = client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS)
    assert res_get.status_code == 200
    assert res_get.get_json()["version"] == "2.1.0"


# ── POST guards are preserved (HTTPS + license resolution) ───────────────────
def test_update_latest_post_keeps_guards(client):
    _customer, lic = _customer_with_license()
    # HTTPS still required on POST.
    assert client.post(UPDATE_URL, json=_envelope(lic.license_key),
                       base_url="http://license-panel.test").status_code == 426
    # unknown license still rejected on POST.
    assert client.post(UPDATE_URL, json=_envelope("NOSUCHLICENSEKEY0000000000000000"),
                       base_url=HTTPS).status_code == 401


# ── nothing published → version:null ─────────────────────────────────────────
def test_update_latest_empty_returns_null(client):
    _customer, lic = _customer_with_license()
    res = client.get(UPDATE_URL, json=_envelope(lic.license_key), base_url=HTTPS)
    assert res.status_code == 200
    assert res.get_json() == {"version": None}


# ── a draft (unpublished) release is NOT served ──────────────────────────────
def test_update_latest_ignores_unpublished_draft(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    mu.publish_release(version="2.0.0", changelog_md="draft", published=False)
    db.session.commit()
    res = client.get(UPDATE_URL, json=_envelope(lic.license_key), base_url=HTTPS)
    assert res.get_json() == {"version": None}


# ── Arabic markdown round-trips exactly ──────────────────────────────────────
def test_changelog_markdown_round_trips(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    md = "# الإصدار ٣\n\n## المزايا\n- دعم **RTL**\n- إصلاح `الجسر`\n\n> ملاحظة: اختياري"
    mu.publish_release(version="3.0.0", changelog_md=md)
    db.session.commit()
    body = client.get(UPDATE_URL, json=_envelope(lic.license_key), base_url=HTTPS).get_json()
    assert body["changelog_md"] == md


# ── "latest" = highest semver, not string/date order ─────────────────────────
def test_latest_picks_highest_semver(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    # publish an OLDER released_at with a HIGHER version to prove semver wins.
    mu.publish_release(version="1.10.0", changelog_md="ten",
                       released_at=utcnow() - timedelta(days=5))
    mu.publish_release(version="1.9.0", changelog_md="nine",
                       released_at=utcnow())
    db.session.commit()
    body = client.get(UPDATE_URL, json=_envelope(lic.license_key), base_url=HTTPS).get_json()
    assert body["version"] == "1.10.0"


# ── per-customer targeting never leaks another customer's release ────────────
def test_targeting_subset_isolates_customers(client):
    from app.services import module_updates as mu
    cust_a, lic_a = _customer_with_license(name="Alpha")
    cust_b, lic_b = _customer_with_license(name="Bravo")
    mu.publish_release(version="5.0.0", changelog_md="alpha-only",
                       target_all=False, target_customer_ids=[cust_a.id])
    db.session.commit()

    body_a = client.get(UPDATE_URL, json=_envelope(lic_a.license_key, nonce="a"), base_url=HTTPS).get_json()
    body_b = client.get(UPDATE_URL, json=_envelope(lic_b.license_key, nonce="b"), base_url=HTTPS).get_json()
    assert body_a["version"] == "5.0.0"
    assert body_b == {"version": None}


# ── guard: HTTPS required + unknown license rejected ─────────────────────────
def test_endpoint_requires_https(client):
    _customer, lic = _customer_with_license()
    res = client.get(UPDATE_URL, json=_envelope(lic.license_key), base_url="http://license-panel.test")
    assert res.status_code == 426


def test_endpoint_rejects_unknown_license(client):
    res = client.get(UPDATE_URL, json=_envelope("NOSUCHLICENSEKEY0000000000000000"), base_url=HTTPS)
    assert res.status_code == 401


# ── admin publish UI creates a release the endpoint then serves ──────────────
def test_admin_publish_ui_then_endpoint_serves(client):
    _login_super(client)
    customer, lic = _customer_with_license()
    res = client.post("/admin/updates", data={
        "version": "1.2.3",
        "changelog_md": "## أول إصدار",
        "mandatory": "on",
        "published": "on",
        "target_mode": "all",
    }, follow_redirects=True)
    assert res.status_code == 200
    assert ModuleRelease.query.filter_by(version="1.2.3").count() == 1

    body = client.get(UPDATE_URL, json=_envelope(lic.license_key), base_url=HTTPS).get_json()
    assert body["version"] == "1.2.3"
    assert body["mandatory"] is True
    assert body["changelog_md"] == "## أول إصدار"


def test_admin_publish_ui_rejects_bad_version(client):
    _login_super(client)
    res = client.post("/admin/updates", data={
        "version": "not-a-version", "changelog_md": "x", "target_mode": "all",
    }, follow_redirects=True)
    assert res.status_code == 200
    assert ModuleRelease.query.filter_by(version="not-a-version").count() == 0


# ── per-customer status helper reflects reported vs latest ───────────────────
def test_customer_update_status_outdated_and_uptodate(client):
    from app.services import module_updates as mu
    customer, lic = _customer_with_license()
    mu.publish_release(version="2.0.0", changelog_md="x")
    db.session.commit()
    # instance reports an OLD running version via a signed call.
    client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS)
    st = mu.customer_update_status(customer)
    assert st["state"] == "outdated"
    assert st["current_version"] == "1.0.0" and st["latest_version"] == "2.0.0"

    # now it reports the latest → up_to_date.
    client.get(UPDATE_URL, json=_envelope(lic.license_key, nonce="n2", version="2.0.0"), base_url=HTTPS)
    st2 = mu.customer_update_status(customer)
    assert st2["state"] == "up_to_date"


# ══════════════════════ accumulated / cumulative changelog ══════════════════

def _publish_three(mu):
    mu.publish_release(version="1.1.0", changelog_md="one")
    mu.publish_release(version="1.2.0", changelog_md="two")
    mu.publish_release(version="1.3.0", changelog_md="three")
    db.session.commit()


def test_cumulative_changelog_spans_current_to_latest(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    _publish_three(mu)
    # instance on 1.0.0 missed all three → latest at top + every missed note.
    body = client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS).get_json()
    assert body["version"] == "1.3.0"
    assert [r["version"] for r in body["releases"]] == ["1.3.0", "1.2.0", "1.1.0"]
    # cumulative changelog carries every missed release, newest-first.
    assert body["changelog_md"] == "three\n\n---\n\ntwo\n\n---\n\none"
    assert body["min_version"] is None


def test_cumulative_excludes_current_and_below(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    _publish_three(mu)
    # already on 1.1.0 → only 1.2.0 and 1.3.0 are "missed".
    body = client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.1.0"), base_url=HTTPS).get_json()
    assert body["version"] == "1.3.0"
    assert [r["version"] for r in body["releases"]] == ["1.3.0", "1.2.0"]
    assert "one" not in body["changelog_md"]


def test_current_at_latest_returns_null(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    _publish_three(mu)
    body = client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.3.0"), base_url=HTTPS).get_json()
    assert body == {"version": None}


def test_mandatory_true_if_any_missed_release_mandatory(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    mu.publish_release(version="1.1.0", changelog_md="one", mandatory=True)
    mu.publish_release(version="1.2.0", changelog_md="two", mandatory=False)
    mu.publish_release(version="1.3.0", changelog_md="three", mandatory=False)
    db.session.commit()
    # from 1.0.0 the span includes the mandatory 1.1.0 → top mandatory True.
    b1 = client.get(UPDATE_URL, json=_envelope(lic.license_key, nonce="m1", version="1.0.0"), base_url=HTTPS).get_json()
    assert b1["mandatory"] is True
    # from 1.1.0 the span is 1.2.0/1.3.0 (none mandatory) → False.
    b2 = client.get(UPDATE_URL, json=_envelope(lic.license_key, nonce="m2", version="1.1.0"), base_url=HTTPS).get_json()
    assert b2["mandatory"] is False


def test_min_version_published_on_latest(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    mu.publish_release(version="2.0.0", changelog_md="major", min_version="1.5.0")
    db.session.commit()
    body = client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS).get_json()
    assert body["version"] == "2.0.0"
    assert body["min_version"] == "1.5.0"


def test_current_version_query_param_overrides_envelope(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    mu.publish_release(version="1.5.0", changelog_md="x")
    db.session.commit()
    # envelope says 1.0.0 (would be an update) but query says already at 1.5.0.
    res = client.get(UPDATE_URL + "?current_version=1.5.0",
                     json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS)
    assert res.get_json() == {"version": None}


def test_release_list_entry_shape(client):
    from app.services import module_updates as mu
    _customer, lic = _customer_with_license()
    mu.publish_release(version="1.1.0", changelog_md="notes here", mandatory=True)
    db.session.commit()
    body = client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS).get_json()
    entry = body["releases"][0]
    assert set(entry) == {"version", "released_at", "changelog_md", "mandatory"}
    assert entry["version"] == "1.1.0"
    assert entry["changelog_md"] == "notes here"
    assert entry["mandatory"] is True
    assert entry["released_at"].endswith("Z")


# ── render smoke tests (ASCII/structural asserts, encoding-agnostic) ─────────
def test_updates_page_renders(client):
    from app.services import module_updates as mu
    _login_super(client)
    mu.publish_release(version="1.0.0", changelog_md="notes")
    db.session.commit()
    res = client.get("/admin/updates")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "/api/integration/hoberadius/update/latest" in body   # documented endpoint
    assert res.request.path == "/admin/updates"
    assert "1.0.0" in body                                       # the release row


def test_updates_page_requires_super_admin(client):
    # a real NON-super admin (DB-backed) is bounced by super_admin_required.
    non_super = Admin(username="op1", password_hash="x", full_name="Op",
                      is_super_admin=False, active=True)
    db.session.add(non_super)
    db.session.commit()
    with client.session_transaction() as s:
        s["admin_id"] = non_super.id
    res = client.get("/admin/updates", follow_redirects=False)
    assert res.status_code in (302, 403)
    # and publishing is likewise gated.
    res2 = client.post("/admin/updates", data={"version": "1.0.0", "target_mode": "all"},
                       follow_redirects=False)
    assert res2.status_code in (302, 403)
    assert ModuleRelease.query.filter_by(version="1.0.0").count() == 0


def test_customer_360_shows_update_status(client):
    from app.services import module_updates as mu
    _login_super(client)
    customer, lic = _customer_with_license()
    mu.publish_release(version="9.9.9", changelog_md="big")
    db.session.commit()
    # report an old running version so the 360 shows "outdated" with the number.
    client.get(UPDATE_URL, json=_envelope(lic.license_key, version="1.0.0"), base_url=HTTPS)
    res = client.get(f"/admin/customers/{customer.id}")
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert "9.9.9" in body        # latest advertised
    assert "1.0.0" in body        # reported running version
