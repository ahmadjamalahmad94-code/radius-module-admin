"""Pure TweetSMS (tweetsms.ps) legacy HTTP API adapter.

No Flask, no DB — just URL building, an HTTP GET, and response parsing, so the
whole thing is trivially unit-testable. The OWNER's single provider account is
used to reach his own customers; credentials are passed in (resolved + decrypted
by ``settings.py``) and are NEVER logged or placed in exception text here.

Wire contract (legacy API):

* **Send**   ``GET https://www.tweetsms.ps/api.php?comm=sendsms&api_key=<KEY>
              &to=<MOBILE>&message=<TEXT>&sender=<SENDER>``
              (``&user=&pass=`` may replace ``api_key``).
* **Balance** ``GET …?comm=chk_balance&api_key=<KEY>`` (or user/pass).

Response is PLAIN TEXT, one ``Result:SMS_ID:mobileNumber`` triple per recipient.
``Result`` ``1`` = success (``SMS_ID`` is the provider id). Per-message failures:
``-2`` invalid destination, ``-999`` provider failed, ``u`` unknown. Global
errors arrive as a bare code: ``-100`` missing params, ``-110`` wrong
user/pass/key, ``-113`` not enough balance, ``-115`` sender unavailable,
``-116`` invalid sender.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Sequence
from urllib.parse import urlencode

#: The single legacy endpoint for both send + balance.
API_URL = "https://www.tweetsms.ps/api.php"

#: Result/error code → Arabic message. Keys cover both per-message result codes
#: (first field of the triple) and bare global error codes.
ERROR_MESSAGES: dict[str, str] = {
    "-100": "بيانات الطلب ناقصة (مُعامل مفقود).",
    "-110": "بيانات الدخول خاطئة (مفتاح API أو اسم المستخدم/كلمة المرور).",
    "-113": "الرصيد غير كافٍ لإتمام الإرسال.",
    "-115": "اسم المُرسِل غير متاح.",
    "-116": "اسم المُرسِل غير صالح.",
    "-2": "رقم الوجهة غير صالح.",
    "-999": "فشل المزوّد في معالجة الرسالة.",
    "u": "حالة غير معروفة من المزوّد.",
}

SUCCESS_MESSAGE = "تم الإرسال بنجاح."
UNKNOWN_MESSAGE = "استجابة غير متوقّعة من المزوّد."
CONNECT_FAIL_PREFIX = "تعذّر الاتصال بمزوّد الرسائل"


def message_for_code(code: str) -> str:
    """Map a provider result/error ``code`` to its Arabic message."""
    code = (code or "").strip()
    if code == "1":
        return SUCCESS_MESSAGE
    return ERROR_MESSAGES.get(code, UNKNOWN_MESSAGE)


# ── result types ─────────────────────────────────────────────────────────

@dataclass
class SmsResult:
    """One recipient's outcome parsed from a response triple."""
    to: str
    ok: bool
    code: str
    sms_id: str
    message: str


@dataclass
class SendOutcome:
    """Whole-request outcome. ``error`` holds a transport/global error (Arabic)
    when the request never produced per-recipient results."""
    ok: bool
    results: list[SmsResult] = field(default_factory=list)
    error: str = ""
    raw: str = ""

    @property
    def first(self) -> SmsResult | None:
        return self.results[0] if self.results else None


# ── credential → query params ────────────────────────────────────────────

def auth_params(creds: dict) -> dict[str, str]:
    """Return the auth query params. ``api_key`` wins; otherwise ``user``+``pass``.

    Never raises — an empty/partial credential simply yields whatever is present,
    and the provider answers with ``-110`` which we map to Arabic.
    """
    api_key = (creds.get("api_key") or "").strip()
    if api_key:
        return {"api_key": api_key}
    user = (creds.get("user") or "").strip()
    pw = (creds.get("pass") or "").strip()
    out: dict[str, str] = {}
    if user:
        out["user"] = user
    if pw:
        out["pass"] = pw
    return out


def build_send_url(creds: dict, to: str | Sequence[str], message: str, sender: str) -> str:
    """Build the ``comm=sendsms`` GET URL.

    ``to`` may be a single number or a sequence (joined by comma — the provider
    accepts a comma-separated list). Arabic ``message`` is URL-encoded as UTF-8.
    """
    if not isinstance(to, str):
        to = ",".join(str(t).strip() for t in to if str(t).strip())
    params = {
        "comm": "sendsms",
        **auth_params(creds),
        "to": to,
        "message": message or "",
        "sender": (sender or "").strip(),
    }
    # urlencode defaults to UTF-8 + quote_plus → Arabic becomes %XX%XX… safely.
    return f"{API_URL}?{urlencode(params)}"


def build_balance_url(creds: dict) -> str:
    """Build the ``comm=chk_balance`` GET URL."""
    params = {"comm": "chk_balance", **auth_params(creds)}
    return f"{API_URL}?{urlencode(params)}"


# ── HTTP (injectable for tests) ──────────────────────────────────────────

HttpGet = Callable[[str, float], str]


def _default_http_get(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "HobeRadius-Licensing/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https host
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


# ── response parsing ─────────────────────────────────────────────────────

def parse_send_response(text: str) -> SendOutcome:
    """Parse a ``sendsms`` plain-text response into a :class:`SendOutcome`.

    Handles both per-recipient triples (``1:SMS_ID:mobile``) and a bare global
    error code (``-113``). Never raises.
    """
    raw = text or ""
    stripped = raw.strip()
    if not stripped:
        return SendOutcome(ok=False, error=UNKNOWN_MESSAGE, raw=raw)

    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    results: list[SmsResult] = []
    for line in lines:
        parts = [p.strip() for p in line.split(":")]
        code = parts[0]
        if len(parts) == 1:
            # Bare token: a lone success "1" or a global error code.
            ok = code == "1"
            results.append(SmsResult(
                to="", ok=ok, code=code, sms_id="", message=message_for_code(code)))
        else:
            sms_id = parts[1] if len(parts) > 1 else ""
            mobile = parts[2] if len(parts) > 2 else ""
            ok = code == "1"
            results.append(SmsResult(
                to=mobile, ok=ok, code=code, sms_id=sms_id, message=message_for_code(code)))

    any_ok = any(r.ok for r in results)
    # A single bare error line is a global error (auth/balance/sender) — surface
    # it as ``error`` too so single-recipient callers get a clean message.
    global_error = ""
    if not any_ok and len(results) == 1 and not results[0].to and results[0].code != "1":
        global_error = results[0].message
    return SendOutcome(ok=any_ok, results=results, error=global_error, raw=raw)


def parse_balance_response(text: str) -> tuple[bool, str, str]:
    """Parse a ``chk_balance`` response → ``(ok, balance_text, arabic_message)``.

    The provider returns a number (optionally ``Balance:123``) on success or a
    bare error code on failure.
    """
    raw = (text or "").strip()
    if not raw:
        return False, "", UNKNOWN_MESSAGE
    token = raw.split(":")[-1].strip() if ":" in raw else raw
    # Known negative error code?
    if token in ERROR_MESSAGES and token.startswith("-"):
        return False, "", ERROR_MESSAGES[token]
    # Numeric balance?
    try:
        float(token)
    except ValueError:
        # Non-numeric, non-mapped → surface raw (trimmed) for the owner.
        return False, "", (raw[:120] or UNKNOWN_MESSAGE)
    return True, token, ""


# ── public send / balance ────────────────────────────────────────────────

def send_sms(creds: dict, to: str | Sequence[str], message: str, sender: str,
             *, timeout: float = 15.0, http_get: HttpGet | None = None) -> SendOutcome:
    """Send ``message`` to ``to`` (single number or list). Never raises — a
    network failure returns ``ok=False`` with an Arabic ``error``."""
    url = build_send_url(creds, to, message, sender)
    getter = http_get or _default_http_get
    try:
        body = getter(url, timeout)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        # ``exc`` here is a transport error (no secret inside the URL leaks: we
        # build our own message and never echo the URL).
        reason = getattr(exc, "reason", None) or exc.__class__.__name__
        return SendOutcome(ok=False, error=f"{CONNECT_FAIL_PREFIX}: {reason}")
    except Exception as exc:  # noqa: BLE001 — must never throw into the request
        return SendOutcome(ok=False, error=f"{CONNECT_FAIL_PREFIX}: {exc.__class__.__name__}")
    return parse_send_response(body)


def check_balance(creds: dict, *, timeout: float = 15.0,
                  http_get: HttpGet | None = None) -> tuple[bool, str, str]:
    """Query the account balance → ``(ok, balance_text, arabic_message)``. Never
    raises."""
    url = build_balance_url(creds)
    getter = http_get or _default_http_get
    try:
        body = getter(url, timeout)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        reason = getattr(exc, "reason", None) or exc.__class__.__name__
        return False, "", f"{CONNECT_FAIL_PREFIX}: {reason}"
    except Exception as exc:  # noqa: BLE001
        return False, "", f"{CONNECT_FAIL_PREFIX}: {exc.__class__.__name__}"
    return parse_balance_response(body)
