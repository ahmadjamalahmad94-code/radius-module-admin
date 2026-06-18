"""The TECHNICAL-SUPPORT communication line — bidirectional, end to end.

Covers the four channels between a customer's radius panel and the provider
licensing panel over the bridge:

  1. Support / tickets  — create (radius→provider), provider reply REACHES the
     radius (pull thread), customer reply over the bridge (radius→provider).
  2. Chat               — poll-based support chat both directions
     (messages/send radius→provider, messages/poll provider→radius).
  3. Activations        — «طلب تفعيل» → provider queue → approve → grant flows
     into the capacity contract (the radius-unlock loop).
  4. Provider→customer  — «رسائل لوحة التراخيص» notices the radius pulls + acks.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    Admin, Customer, CustomerServiceRequest, License, PanelMessage, Plan, utcnow,
)
from app.services.customer_control import build_runtime_contract_for_license

HTTPS = {"base_url": "https://license-panel.test"}


@pytest.fixture()
def cust_lic(app):
    plan = Plan.query.filter_by(slug="pro").one()
    c = Customer(company_name="Support Co", email="support@example.com", status="active")
    db.session.add(c)
    db.session.flush()
    lic = License(customer_id=c.id, plan_id=plan.id, license_key="LIC-SUPPORT-1",
                  status="active", starts_at=utcnow() - timedelta(days=1),
                  expires_at=utcnow() + timedelta(days=365),
                  grace_until=utcnow() + timedelta(days=372))
    db.session.add(lic)
    db.session.commit()
    return c, lic


def _admin(client):
    a = Admin.query.first()
    with client.session_transaction() as s:
        s["admin_id"] = a.id


def _key(lic):
    return {"license_key": lic.license_key}


# ── 1. SUPPORT / TICKETS — bidirectional ──────────────────────────────────────
def test_ticket_create_then_provider_reply_reaches_radius(app, client, cust_lic):
    c, lic = cust_lic
    # radius opens a ticket over the bridge
    r = client.post("/api/integration/hoberadius/service-requests",
                    json={**_key(lic), "service_key": "customer_support",
                          "request_type": "support", "notes": "بحاجة مساعدة في الإعداد"}, **HTTPS)
    assert r.status_code == 201
    ref = r.get_json()["service_request"]["reference"]
    # provider replies from the admin panel
    sr = CustomerServiceRequest.query.filter_by(public_reference=ref).one()
    _admin(client)
    rep = client.post(f"/admin/service-requests/{sr.id}/reply",
                      data={"message": "تم استلام طلبك، سنساعدك الآن."}, follow_redirects=True)
    assert rep.status_code == 200
    # radius PULLS the ticket thread → the provider reply is there
    pull = client.post("/api/integration/hoberadius/service-requests/messages",
                       json={**_key(lic), "reference": ref}, **HTTPS)
    assert pull.status_code == 200
    bodies = [m["body"] for m in pull.get_json()["messages"]]
    assert any("سنساعدك" in b for b in bodies)


def test_customer_reply_over_bridge_lands_on_thread(app, client, cust_lic):
    c, lic = cust_lic
    r = client.post("/api/integration/hoberadius/service-requests",
                    json={**_key(lic), "service_key": "customer_support",
                          "request_type": "support", "notes": "سؤال"}, **HTTPS)
    ref = r.get_json()["service_request"]["reference"]
    # radius posts a customer reply onto the thread
    pull = client.post("/api/integration/hoberadius/service-requests/messages",
                       json={**_key(lic), "reference": ref, "message": "شكرًا، بانتظار الرد"}, **HTTPS)
    assert pull.status_code == 200
    assert any("بانتظار الرد" in m["body"] for m in pull.get_json()["messages"])


def test_ticket_messages_unknown_reference_404(app, client, cust_lic):
    _c, lic = cust_lic
    r = client.post("/api/integration/hoberadius/service-requests/messages",
                    json={**_key(lic), "reference": "SR-NOPE"}, **HTTPS)
    assert r.status_code == 404


# ── 2 & 4. PANEL MESSAGES + CHAT — both directions over the bridge ────────────
def test_provider_notice_is_pulled_and_acked(app, client, cust_lic):
    c, lic = cust_lic
    from app.services import panel_messaging
    with app.app_context():
        panel_messaging.send_to_customer(
            db.session.get(Customer, c.id), body="صيانة مجدولة الليلة", subject="إشعار صيانة",
            channel="notice", importance="warning")
        db.session.commit()
    # radius polls → receives it, marked delivered
    poll = client.post("/api/integration/hoberadius/messages/poll", json=_key(lic), **HTTPS)
    assert poll.status_code == 200
    msgs = poll.get_json()["messages"]
    assert len(msgs) == 1 and msgs[0]["subject"] == "إشعار صيانة" and msgs[0]["importance"] == "warning"
    mid = msgs[0]["id"]
    # a second poll is clean (delivered rows aren't re-sent)
    assert client.post("/api/integration/hoberadius/messages/poll", json=_key(lic), **HTTPS).get_json()["count"] == 0
    # radius acks seen
    ack = client.post("/api/integration/hoberadius/messages/ack",
                      json={**_key(lic), "message_ids": [mid]}, **HTTPS)
    assert ack.status_code == 200 and ack.get_json()["acked"] == 1
    with app.app_context():
        assert db.session.get(PanelMessage, mid).seen_at is not None


def test_customer_chat_message_lands_in_provider_inbox(app, client, cust_lic):
    c, lic = cust_lic
    send = client.post("/api/integration/hoberadius/messages/send",
                       json={**_key(lic), "channel": "chat", "body": "عندي استفسار عاجل"}, **HTTPS)
    assert send.status_code == 201
    with app.app_context():
        row = PanelMessage.query.filter_by(customer_id=c.id, direction="from_customer").one()
        assert row.channel == "chat" and row.body == "عندي استفسار عاجل"
        assert row.delivered_at is not None  # inbound is delivered on arrival


def test_empty_message_rejected(app, client, cust_lic):
    _c, lic = cust_lic
    r = client.post("/api/integration/hoberadius/messages/send",
                    json={**_key(lic), "body": "   "}, **HTTPS)
    assert r.status_code == 422


def test_messages_require_https(app, client, cust_lic):
    _c, lic = cust_lic
    r = client.post("/api/integration/hoberadius/messages/poll", json=_key(lic))  # http
    assert r.status_code == 426


# ── admin side: compose + thread render ───────────────────────────────────────
def test_admin_can_send_and_view_thread(app, client, cust_lic):
    c, lic = cust_lic
    _admin(client)
    snd = client.post(f"/admin/customers/{c.id}/messages",
                      data={"channel": "chat", "importance": "info", "body": "مرحبًا، كيف نساعدك؟"},
                      follow_redirects=True)
    assert snd.status_code == 200
    page = client.get(f"/admin/customers/{c.id}/messages")
    assert page.status_code == 200
    assert "كيف نساعدك" in page.get_data(as_text=True)
    with app.app_context():
        assert PanelMessage.query.filter_by(customer_id=c.id, direction="to_customer").count() == 1


# ── 3. ACTIVATIONS — request → approve → grant → contract (the unlock loop) ───
def test_activation_request_approve_flows_into_contract(app, client, cust_lic):
    c, lic = cust_lic
    # radius requests SMS activation over the bridge
    r = client.post("/api/integration/hoberadius/service-requests",
                    json={**_key(lic), "service_key": "sms_gateway",
                          "request_type": "activation", "desired_limits": {"package_messages": 3000}}, **HTTPS)
    assert r.status_code == 201
    ref = r.get_json()["service_request"]["reference"]
    sr = CustomerServiceRequest.query.filter_by(public_reference=ref).one()
    # provider approves → grant
    _admin(client)
    ap = client.post(f"/admin/service-requests/{sr.id}/approve", data={}, follow_redirects=False)
    assert ap.status_code in (301, 302)
    db.session.expire_all()
    # grant is live in the capacity contract the radius pulls
    sms = build_runtime_contract_for_license(lic, license_active=True, status="active")["services"]["sms_gateway"]
    assert sms["enabled"] is True
    assert sms["limits"]["sms_package_credits"] == 3000
