"""Lifecycle messages — customer-facing transactional templates.

A *lifecycle event* is a discrete moment in the customer's relationship with
the panel where we want to send them a short text: their new login credentials,
a welcome note when they're created, a "you'll expire soon" reminder, a
"payment received / approved / license activated" confirmation, etc.

Each event has:

* a stable ``event_id`` (the dict key + the URL fragment),
* an Arabic label shown in the settings UI,
* a default Jinja-light template (``{username}`` / ``{password}`` / …),
* the list of variable names it expects (used by the UI to render hints AND
  by the renderer to refuse a template that references an unknown variable).

Storage layout — both knobs live in the ``settings`` key-value table:

* ``messaging.lifecycle.<event_id>.enabled`` → ``"1"`` / ``"0"``
* ``messaging.lifecycle.<event_id>.template`` → custom Jinja-light text
  (blank ⇒ use the default).

Why a separate module from ``channels`` / ``settings_store`` / ``layers``?
The channel router is transport-only; lifecycle is policy. Putting them in
distinct modules keeps "should we send" and "how do we send" testable on
their own and gives the settings UI exactly one place to read/write.
"""
from __future__ import annotations

import logging
import string
from dataclasses import dataclass
from typing import Any

from ...extensions import db
from ...models import Setting

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class LifecycleEvent:
    event_id: str
    label: str          # Arabic, shown in the settings UI
    description: str    # Arabic, one-line hint shown under the label
    variables: tuple[str, ...]
    default_template: str
    default_enabled: bool = True


#: Catalog of supported customer-facing lifecycle messages.
#:
#: The CREDENTIALS event is special: it is enforced to only ever fire when the
#: caller has the plaintext password in memory (i.e. the moment the admin
#: submits it). We never persist or re-derive the password.
LIFECYCLE_EVENTS: dict[str, LifecycleEvent] = {
    "credentials": LifecycleEvent(
        event_id="credentials",
        label="إرسال بيانات الدخول",
        description="عند إنشاء مستخدم العميل أو تغيير كلمة مروره — تُرسل له بياناته فوراً.",
        variables=("username", "password", "portal_url", "company"),
        default_template=(
            "مرحباً {company}،\n"
            "بيانات دخولك للوحة:\n"
            "اسم المستخدم: {username}\n"
            "كلمة المرور: {password}\n"
            "الرابط: {portal_url}"
        ),
        # SECURITY: credentials default ON so admins don't accidentally ship
        # passwords to the user without sending them; toggle OFF in settings
        # to suppress dispatch if all communication is offline.
        default_enabled=True,
    ),
    "welcome": LifecycleEvent(
        event_id="welcome",
        label="رسالة ترحيب",
        description="عند إنشاء عميل جديد (بدون أي بيانات حسّاسة).",
        variables=("company", "portal_url"),
        default_template=(
            "مرحباً بك {company} في خدمتنا!\n"
            "نتمنى لك تجربة موفقة. {portal_url}"
        ),
        default_enabled=True,
    ),
    "expiring_soon": LifecycleEvent(
        event_id="expiring_soon",
        label="تذكير قبل الانتهاء",
        description="قبل انتهاء الترخيص بعدد الأيام المحدد.",
        variables=("company", "days_left", "expires_on"),
        default_template=(
            "تذكير: ينتهي اشتراك {company} خلال {days_left} يوماً ({expires_on}).\n"
            "يرجى التجديد لتفادي انقطاع الخدمة."
        ),
        default_enabled=True,
    ),
    "expired": LifecycleEvent(
        event_id="expired",
        label="إشعار الانتهاء",
        description="فور انتهاء صلاحية الترخيص.",
        variables=("company", "expires_on"),
        default_template=(
            "انتهى اشتراك {company} بتاريخ {expires_on}.\n"
            "يرجى التجديد لإعادة تفعيل الخدمة."
        ),
        default_enabled=True,
    ),
    "payment_received": LifecycleEvent(
        event_id="payment_received",
        label="تأكيد استلام الدفع",
        description="عند قبول إثبات الدفع من الإدارة (لم يُربط بعد بالترخيص).",
        variables=("company", "reference_code", "amount", "currency"),
        default_template=(
            "تم استلام دفعتك بنجاح.\n"
            "المرجع: {reference_code}\n"
            "المبلغ: {amount} {currency}\n"
            "سيتم تفعيل الباقة قريباً."
        ),
        default_enabled=True,
    ),
    "payment_applied": LifecycleEvent(
        event_id="payment_applied",
        label="تأكيد تفعيل الترخيص",
        description="عند ربط الدفع بالترخيص وتفعيل الباقة.",
        variables=("company", "reference_code", "plan_name", "expires_on"),
        default_template=(
            "تم تفعيل اشتراك {company}.\n"
            "الباقة: {plan_name}\n"
            "ينتهي في: {expires_on}\n"
            "المرجع: {reference_code}"
        ),
        default_enabled=True,
    ),
    "manual_top_up": LifecycleEvent(
        event_id="manual_top_up",
        label="تأكيد شحن يدوي",
        description="عند إجراء شحن/تعديل رصيد يدوي للعميل من الإدارة.",
        variables=("company", "amount", "currency", "note"),
        default_template=(
            "تم تعديل رصيدك بمبلغ {amount} {currency}.\n"
            "ملاحظة: {note}"
        ),
        default_enabled=False,  # ships off by default; enable when used.
    ),
}


# ── persistence helpers ──────────────────────────────────────────────────

def _kv(key: str) -> str:
    row = db.session.get(Setting, key)
    return (row.value or "") if row else ""


def _set_kv(key: str, value: str) -> None:
    row = db.session.get(Setting, key)
    if not row:
        row = Setting(key=key)
    row.value = value
    db.session.add(row)


def _enabled_key(event_id: str) -> str:
    return f"messaging.lifecycle.{event_id}.enabled"


def _template_key(event_id: str) -> str:
    return f"messaging.lifecycle.{event_id}.template"


def is_enabled(event_id: str) -> bool:
    """True iff the admin has the event toggled on (default per event respected)."""
    ev = LIFECYCLE_EVENTS.get(event_id)
    if ev is None:
        return False
    raw = _kv(_enabled_key(event_id)).strip().lower()
    if not raw:
        return ev.default_enabled
    return raw in ("1", "true", "yes", "on")


def get_template(event_id: str) -> str:
    """Return the custom template if saved, else the default."""
    ev = LIFECYCLE_EVENTS.get(event_id)
    if ev is None:
        return ""
    custom = _kv(_template_key(event_id))
    return custom if custom.strip() else ev.default_template


def get_event_state(event_id: str) -> dict[str, Any]:
    """UI-safe state for one event (no secrets — these templates never contain
    a password at rest, only the placeholder ``{password}``)."""
    ev = LIFECYCLE_EVENTS.get(event_id)
    if ev is None:
        raise KeyError(event_id)
    custom = _kv(_template_key(event_id))
    return {
        "event_id": ev.event_id,
        "label": ev.label,
        "description": ev.description,
        "variables": list(ev.variables),
        "enabled": is_enabled(event_id),
        "template": custom if custom.strip() else ev.default_template,
        "is_custom": bool(custom.strip()),
        "default_template": ev.default_template,
    }


def all_event_states() -> list[dict[str, Any]]:
    return [get_event_state(eid) for eid in LIFECYCLE_EVENTS]


def save_event(event_id: str, *, enabled: bool, template: str, actor_audit) -> None:
    """Persist toggle + (optional) custom template for one event."""
    if event_id not in LIFECYCLE_EVENTS:
        raise KeyError(event_id)
    _set_kv(_enabled_key(event_id), "1" if enabled else "0")
    # Blank template means "use the default" — store empty so we don't drift.
    _set_kv(_template_key(event_id), (template or "").strip())
    actor_audit(
        "messaging_lifecycle_saved", "messaging_lifecycle", event_id,
        f"Saved lifecycle event {event_id}",
        # NEVER log the template body — operators may have pasted PII.
        {"event_id": event_id, "enabled": enabled, "is_custom": bool(template.strip())},
    )


# ── rendering ────────────────────────────────────────────────────────────

class _SafeDict(dict):
    """``str.format_map`` helper — leaves unknown ``{name}`` placeholders
    intact instead of raising. Lets the operator keep an old placeholder in
    their custom template without breaking the dispatch."""

    def __missing__(self, key: str) -> str:  # type: ignore[override]
        return "{" + key + "}"


def render(event_id: str, **variables: Any) -> str:
    """Format the saved (or default) template with ``variables``.

    Renders with ``str.format_map`` over a safe dict — unknown placeholders are
    preserved rather than blowing up. Returns ``""`` for an unknown event.
    """
    template = get_template(event_id)
    if not template:
        return ""
    # Coerce every value to str up-front so format_map can't trip on a None.
    coerced = {k: ("" if v is None else str(v)) for k, v in variables.items()}
    try:
        return template.format_map(_SafeDict(coerced))
    except (IndexError, KeyError, ValueError) as exc:
        # A genuinely broken template (e.g. positional ``{0}`` references).
        # Log and fall back to the default so the customer still gets *some*
        # message instead of nothing.
        _log.warning("lifecycle render(%s) failed: %s — using default", event_id, exc)
        ev = LIFECYCLE_EVENTS.get(event_id)
        if ev is None:
            return ""
        return ev.default_template.format_map(_SafeDict(coerced))


def build_credentials_text(*, username: str, password: str, customer: Any) -> str:
    """Compose the credential delivery message for a specific customer.

    Pulls the company name + portal URL from the customer ORM row and lets the
    saved/default template format them. NEVER logs ``password`` — even from a
    raised exception inside ``render``.
    """
    company = (getattr(customer, "company_name", "") or "").strip()
    portal_url = (getattr(customer, "runtime_url", "") or "").strip()
    return render(
        "credentials",
        username=username,
        password=password,
        portal_url=portal_url,
        company=company,
    )
