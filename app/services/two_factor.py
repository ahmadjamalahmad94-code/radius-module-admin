"""2FA/TOTP لمديري اللوحة (إعادة تصميم 2026-07).

TOTP قياسي (RFC 6238) متوافق مع Google Authenticator / Authy / 1Password.
السرّ يُخزَّن على ``Admin.totp_secret`` (base32). التفعيل يتطلب إثبات رمز صحيح
مرة واحدة قبل قلب ``totp_enabled`` — كي لا يُقفل المدير نفسه بسرّ لم يمسحه.
"""
from __future__ import annotations

import base64
import io

import pyotp

_ISSUER = "HobeRadius Admin"


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_name: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_name or "admin", issuer_name=_ISSUER
    )


def verify(secret: str, code: str) -> bool:
    """يتحقق من رمز TOTP بنافذة ±1 لتحمّل انزياح الساعة."""
    if not secret or not code:
        return False
    code = str(code).strip().replace(" ", "")
    if not code.isdigit():
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:  # noqa: BLE001
        return False


def qr_data_uri(secret: str, account_name: str) -> str:
    """يبني رمز QR كـ data:image/png;base64 لعرضه مباشرة في القالب (بلا CDN)."""
    import qrcode  # noqa: PLC0415

    img = qrcode.make(provisioning_uri(secret, account_name))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"
