from __future__ import annotations


class WhatsAppPhoneError(Exception):
    """Raised when a phone number cannot be normalized for WhatsApp."""


_INVALID_MSG = "رقم الهاتف غير صالح للإرسال عبر واتساب"

# Arabic-Indic (٠-٩, U+0660..U+0669) and Eastern Arabic-Indic / Persian
# (۰-۹, U+06F0..U+06F9) digit folding to ASCII.
_DIGIT_FOLD = {
    "٠": "0", "١": "1", "٢": "2", "٣": "3", "٤": "4",
    "٥": "5", "٦": "6", "٧": "7", "٨": "8", "٩": "9",
    "۰": "0", "۱": "1", "۲": "2", "۳": "3", "۴": "4",
    "۵": "5", "۶": "6", "۷": "7", "۸": "8", "۹": "9",
}

# Characters stripped as visual separators.
_STRIP_CHARS = set(" \t -()[].‏‎")

# Country prefixes that already carry the full international number.
_KNOWN_CC = ("970", "972")

# Minimum digit count for the national significant part (after country code).
_MIN_NSN_DIGITS = 8


def _fold_and_clean(phone: str) -> str:
    out: list[str] = []
    for ch in phone:
        folded = _DIGIT_FOLD.get(ch, ch)
        if folded == "+":
            out.append("+")
        elif folded.isdigit() and folded.isascii():
            out.append(folded)
        elif folded in _STRIP_CHARS:
            continue
        else:
            # Unknown character (letters, symbols) -> mark as invalid.
            out.append("?")
    return "".join(out)


def normalize_phone_for_whatsapp(phone: str, default_country: str = "PS") -> str:
    """Normalize a phone number to E.164 (with leading "+") for WhatsApp.

    - Folds Arabic-Indic / Eastern digits to ASCII; strips spaces, dashes,
      parentheses, dots.
    - Accepts a leading "+"; converts a "00" international prefix to "+".
    - Recognizes 970/972 (Palestine / Israel) prefixes already present.
    - For ``default_country="PS"``: a 10-digit local number starting "05"
      becomes +970… (drop the leading 0, prepend 970).

    Raises ``WhatsAppPhoneError`` on empty / non-numeric / too-short input.
    """
    if not phone or not phone.strip():
        raise WhatsAppPhoneError(_INVALID_MSG)

    cleaned = _fold_and_clean(phone)
    if "?" in cleaned or not cleaned:
        raise WhatsAppPhoneError(_INVALID_MSG)

    has_plus = cleaned.startswith("+")
    digits = cleaned[1:] if has_plus else cleaned

    # A "+" may only appear at the very start.
    if "+" in digits or not digits.isdigit():
        raise WhatsAppPhoneError(_INVALID_MSG)

    # "00" international prefix -> drop it and treat as international.
    if not has_plus and digits.startswith("00"):
        digits = digits[2:]
        has_plus = True

    country = (default_country or "").strip().upper()

    if has_plus:
        # Already international form (came in with + or via 00).
        national = _strip_known_cc(digits)
        if national is None:
            # Some other country code; accept as-is if long enough.
            if len(digits) < (1 + _MIN_NSN_DIGITS):
                raise WhatsAppPhoneError(_INVALID_MSG)
            return "+" + digits
        if len(national) < _MIN_NSN_DIGITS:
            raise WhatsAppPhoneError(_INVALID_MSG)
        return "+" + digits

    # No "+" and no "00": digits could still lead with a known country code.
    national = _strip_known_cc(digits)
    if national is not None:
        if len(national) < _MIN_NSN_DIGITS:
            raise WhatsAppPhoneError(_INVALID_MSG)
        return "+" + digits

    # Pure local number. Apply default-country rules.
    if country == "PS":
        if digits.startswith("05") and len(digits) == 10:
            return "+970" + digits[1:]
        raise WhatsAppPhoneError(_INVALID_MSG)

    # Unknown default country and no recognizable prefix: cannot normalize.
    raise WhatsAppPhoneError(_INVALID_MSG)


def _strip_known_cc(digits: str) -> str | None:
    """If ``digits`` begins with a known country code, return the national part.

    Returns ``None`` when no known country code is detected.
    """
    for cc in _KNOWN_CC:
        if digits.startswith(cc):
            return digits[len(cc):]
    return None
