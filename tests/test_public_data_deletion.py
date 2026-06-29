"""Public Data Deletion Instructions page (/data-deletion).

Meta/Facebook requires a public, reachable "User data deletion" URL for the
WhatsApp Embedded Signup app. The page must render for an ANONYMOUS (logged-out)
visitor, carry the Arabic heading, the contact email, and an English section
that Meta reviewers can read.
"""
from __future__ import annotations


def test_data_deletion_public_and_complete(client):
    # Anonymous client — no login, no session.
    resp = client.get("/data-deletion")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)

    # Arabic primary heading.
    assert "تعليمات حذف البيانات" in body
    # Contact email (brand default, since TestingConfig leaves SUPPORT_EMAIL at
    # the generic "support@example.com" placeholder).
    assert "support@hoberadius.com" in body
    # English section for Meta reviewers.
    assert "Data Deletion Instructions (English)" in body
    # Mentions the two deletion paths (self-service portal + email).
    assert "/portal" in body


def test_data_deletion_linked_from_privacy_and_terms(client):
    for path in ("/privacy", "/terms"):
        body = client.get(path).get_data(as_text=True)
        assert '/data-deletion' in body


def test_data_deletion_honors_configured_support_email(app):
    # When a real SUPPORT_EMAIL is configured, the page shows it instead of the
    # brand fallback.
    app.config["SUPPORT_EMAIL"] = "privacy@example.org"
    body = app.test_client().get("/data-deletion").get_data(as_text=True)
    assert "privacy@example.org" in body
