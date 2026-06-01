from __future__ import annotations

import pytest

from app.services.whatsapp.crypto import (
    WhatsAppCryptoError,
    decrypt_secret,
    encrypt_secret,
    mask_secret,
)


def test_encrypt_decrypt_round_trip(app):
    secret = "EAABsbCS1iHgBO9xQ_super_secret_meta_token"
    with app.app_context():
        token = encrypt_secret(secret)
        assert token
        assert token != secret
        assert decrypt_secret(token) == secret


def test_encrypt_empty_returns_empty(app):
    with app.app_context():
        assert encrypt_secret("") == ""
        assert decrypt_secret("") == ""


def test_mask_hides_middle_and_never_contains_full_secret(app):
    secret = "EAABsbCS1iHgBO9xQ"
    with app.app_context():
        masked = mask_secret(secret)
    assert masked != secret
    assert secret not in masked
    assert "…" in masked
    assert masked.startswith("EAAB")
    assert masked.endswith("9xQ")
    # The middle of the secret must not leak.
    assert "sbCS1iHgBO" not in masked


def test_mask_empty_returns_dash():
    assert mask_secret("") == "—"


def test_decrypt_tampered_token_raises(app):
    secret = "another-secret-value"
    with app.app_context():
        token = encrypt_secret(secret)
        tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        with pytest.raises(WhatsAppCryptoError):
            decrypt_secret(tampered)


def test_decrypt_garbage_token_raises(app):
    with app.app_context():
        with pytest.raises(WhatsAppCryptoError):
            decrypt_secret("not-a-valid-fernet-token")


def test_encrypt_without_key_raises(app):
    with app.app_context():
        app.config["WHATSAPP_FERNET_KEY"] = ""
        with pytest.raises(WhatsAppCryptoError):
            encrypt_secret("needs-a-key")
