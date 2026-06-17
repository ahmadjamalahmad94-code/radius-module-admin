"""Tests for the public landing page + Landing CMS (radius-module-admin)."""
from __future__ import annotations

from app.extensions import db
from app.models import (
    Admin,
    LandingContactMethod,
    LandingItem,
    LandingPage,
    LandingSection,
    LandingSocialLink,
)
from app.services.landing_cms import seed_landing_defaults


def _login(client, app):
    with app.app_context():
        admin_id = Admin.query.first().id
    with client.session_transaction() as s:
        s["admin_id"] = admin_id


def _html(client):
    return client.get("/").get_data(as_text=True)


# 1
def test_public_page_renders_from_db(client):
    html = _html(client)
    assert "منصة ذكية لإدارة شبكات الإنترنت" in html
    assert "public_landing.css" in html


# 2
def test_hidden_section_not_rendered(client, app):
    with app.app_context():
        sec = LandingSection.query.filter_by(section_key="faq").first()
        sec.is_visible = False
        db.session.commit()
    html = _html(client)
    assert 'id="faq"' not in html


# 3
def test_hidden_item_not_rendered(client, app):
    marker = "بطاقة-مخفية-فريدة-XZ"
    with app.app_context():
        feat = LandingSection.query.filter_by(section_key="features").first()
        item = feat.items.first()
        item.title = marker
        db.session.commit()
    assert marker in _html(client)          # visible → shows
    with app.app_context():
        feat = LandingSection.query.filter_by(section_key="features").first()
        item = feat.items.first()
        item.is_visible = False
        db.session.commit()
    assert marker not in _html(client)      # hidden → gone


# 4
def test_section_order_respected(client, app):
    html = _html(client)
    # features section appears before footer brand text by default order
    assert html.index('id="features"') < html.index('id="faq"')
    with app.app_context():
        feats = LandingSection.query.filter_by(section_key="features").first()
        why = LandingSection.query.filter_by(section_key="why_hoberadius").first()
        feats.sort_order, why.sort_order = why.sort_order, feats.sort_order
        db.session.commit()
    html2 = _html(client)
    assert html2.index('id="why_hoberadius"') < html2.index('id="features"')


# 5
def test_item_order_respected(client, app):
    a, b = "آيتم-أ-فريد", "آيتم-ب-فريد"
    with app.app_context():
        feat = LandingSection.query.filter_by(section_key="features").first()
        items = feat.items.order_by(LandingItem.sort_order).all()
        first, second = items[0], items[1]
        first.title, second.title = a, b
        first.sort_order, second.sort_order = second.sort_order, first.sort_order
        db.session.commit()
    html = _html(client)
    assert html.index(b) < html.index(a)


# 6 + 7
def test_social_links_visibility_and_empty_url(client, app):
    with app.app_context():
        db.session.add(LandingSocialLink(platform="facebook", url="https://facebook.com/hoberadius",
                                         icon_name="facebook", is_visible=True, sort_order=10))
        db.session.add(LandingSocialLink(platform="instagram", url="https://instagram.com/x",
                                         icon_name="instagram", is_visible=False, sort_order=20))
        db.session.add(LandingSocialLink(platform="x", url="", icon_name="x-twitter",
                                         is_visible=True, sort_order=30))
        db.session.commit()
    html = _html(client)
    assert "facebook.com/hoberadius" in html       # visible + url
    assert "instagram.com/x" not in html            # hidden
    # empty-url link must not render an empty anchor for it
    assert html.count('class="lp-social"') <= 1


# 8
def test_contact_methods_visibility(client, app):
    with app.app_context():
        db.session.add(LandingContactMethod(method_type="email", label="الدعم",
                                            value="help@hoberadius.test", is_visible=True, sort_order=5))
        db.session.add(LandingContactMethod(method_type="phone", label="هاتف",
                                            value="", is_visible=True, sort_order=6))
        db.session.commit()
    html = _html(client)
    assert "help@hoberadius.test" in html
    # empty-value contact must not render
    assert html.count("tel:") == 0


# 9
def test_admin_cms_requires_login(client):
    r = client.get("/admin/landing/", follow_redirects=False)
    assert r.status_code in (301, 302, 308)
    if r.status_code in (301, 302):
        assert "/login" in r.headers.get("Location", "")


# 10
def test_admin_can_update_section_title(client, app):
    _login(client, app)
    with app.app_context():
        sec = LandingSection.query.filter_by(section_key="features").first()
        sid = sec.id
    client.post(f"/admin/landing/sections/{sid}", data={"title": "مزايا منصتنا المحدثة"})
    with app.app_context():
        assert db.session.get(LandingSection, sid).title == "مزايا منصتنا المحدثة"
    # public page via a fresh anonymous client (logged-in admin is redirected to dashboard)
    anon = app.test_client()
    assert "مزايا منصتنا المحدثة" in anon.get("/").get_data(as_text=True)


# 11
def test_admin_can_toggle_item_visibility(client, app):
    _login(client, app)
    with app.app_context():
        feat = LandingSection.query.filter_by(section_key="features").first()
        item = feat.items.first()
        iid, before = item.id, item.is_visible
    client.post(f"/admin/landing/items/{iid}/toggle")
    with app.app_context():
        assert db.session.get(LandingItem, iid).is_visible != before


# 12
def test_seed_is_idempotent(client, app):
    with app.app_context():
        seed_landing_defaults()
        seed_landing_defaults()
        assert LandingPage.query.filter_by(slug="home").count() == 1
        page = LandingPage.query.filter_by(slug="home").first()
        # 12 default sections + 2 app sections (downloads, cardprint_intro),
        # each exactly once (no duplicates ⇒ seed + ensure_app_sections idempotent).
        keys = [s.section_key for s in page.sections]
        assert len(keys) == len(set(keys)) == 14
        assert {"downloads", "cardprint_intro"} <= set(keys)


# 13
def test_no_forbidden_claims_in_seed(client):
    html = _html(client)
    forbidden = ["14 بوابة", "أكثر من 14", "UltraMsg", "Gemini", "Messenger",
                 "Firebase", "ISO جاهز", "Official Meta", "PayPal", "Stripe",
                 "Fawry", "PayMob", "رسالة مجانية", "One-click"]
    present = [f for f in forbidden if f in html]
    assert present == [], f"forbidden claims present: {present}"


# 14
def test_arabic_rtl_present(client):
    html = _html(client)
    assert 'dir="rtl"' in html
    assert 'lang="ar"' in html


# 15
def test_content_is_db_driven_not_hardcoded(client, app):
    with app.app_context():
        hero = LandingSection.query.filter_by(section_key="hero").first()
        hero.title = "عنوان مخصص من قاعدة البيانات"
        db.session.commit()
    html = _html(client)
    assert "عنوان مخصص من قاعدة البيانات" in html
