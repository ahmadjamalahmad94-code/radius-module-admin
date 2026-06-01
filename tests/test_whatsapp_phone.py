from __future__ import annotations

import pytest

from app.services.whatsapp.phone import (
    WhatsAppPhoneError,
    normalize_phone_for_whatsapp,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0598765432", "+970598765432"),
        ("0568123456", "+970568123456"),
        ("٠٥٩٨٧٦٥٤٣٢", "+970598765432"),
        ("+972598765432", "+972598765432"),
        ("00970598765432", "+970598765432"),
        # Separators must be stripped.
        ("059-876-5432", "+970598765432"),
        ("+970 59 876 5432", "+970598765432"),
    ],
)
def test_normalize_valid(raw, expected):
    assert normalize_phone_for_whatsapp(raw) == expected


@pytest.mark.parametrize("raw", ["123", "", "   ", "abc", "059876543x"])
def test_normalize_rejects_invalid(raw):
    with pytest.raises(WhatsAppPhoneError):
        normalize_phone_for_whatsapp(raw)
