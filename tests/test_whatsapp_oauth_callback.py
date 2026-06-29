"""Meta WhatsApp Embedded Signup OAuth redirect landing page.

The public ``/integrations/whatsapp/callback`` endpoint is the redirect URI
registered in the Meta App. It must render a 200 RTL page for both the success
(``code``) and denial (``error``) redirects, WITHOUT exchanging the code or
leaking secrets. No Meta network is touched.
"""
from __future__ import annotations

CALLBACK_URL = "/integrations/whatsapp/callback"
ALIAS_URL = "/portal/integrations/whatsapp/callback"


def test_callback_with_code_renders_success(client):
    resp = client.get(CALLBACK_URL, query_string={"code": "test_code", "state": "test_state"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "تم استلام رمز الربط بنجاح" in body
    # The raw authorization code is never echoed into the page.
    assert "test_code" not in body


def test_callback_with_error_renders_safe_message(client):
    resp = client.get(CALLBACK_URL, query_string={"error": "access_denied"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "تعذّر إكمال ربط واتساب" in body
    # The Meta error string is surfaced (escaped) to the user.
    assert "access_denied" in body


def test_callback_error_description_is_html_escaped(client):
    resp = client.get(
        CALLBACK_URL,
        query_string={"error": "access_denied", "error_description": "<script>x</script>"},
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Jinja autoescaping must neutralize any markup in Meta-provided text.
    assert "<script>x</script>" not in body
    assert "&lt;script&gt;" in body


def test_callback_bare_renders_neutral_page(client):
    resp = client.get(CALLBACK_URL)
    assert resp.status_code == 200
    assert "صفحة ربط واتساب" in resp.get_data(as_text=True)


def test_callback_alias_path_also_works(client):
    resp = client.get(ALIAS_URL, query_string={"code": "test_code", "state": "test_state"})
    assert resp.status_code == 200
    assert "تم استلام رمز الربط بنجاح" in resp.get_data(as_text=True)
