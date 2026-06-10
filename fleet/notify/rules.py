"""fleet.notify.rules — Phase 9 alert rule matrix.

Maps each Phase-2 :class:`Event` kind to:

* a human-readable Arabic title (used as the alert subject),
* a body composer that builds the SHORT message + the SHORT report
  ("what happened, which node, how many users moved, what the owner
  should know") from the event's ``detail`` payload,
* a stable :func:`dedupe_key` so a storm of identical events collapses to
  one queued/sent alert (see :class:`fleet.notify.models_alert.Alert`),
* a default severity (used when the producer didn't stamp one).

Pure functions only — no DB, no I/O, no Flask. The :mod:`fleet.notify.notifier`
module composes these into actual ``Alert`` rows and dispatches them via the
messaging channel router.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .models_alert import Event


@dataclass(frozen=True)
class AlertSpec:
    """The result of running a rule against one event."""

    kind: str                 # the event kind (echoed for callers)
    title: str                # short Arabic subject (used in the alerts list)
    body: str                 # composed message body (Arabic, SMS-friendly)
    dedupe_key: str | None    # None ⇒ opt out of dedupe
    severity: str             # info | warn | crit
    default_enabled: bool     # if the owner hasn't set a per-kind preference


# ── helpers ───────────────────────────────────────────────────────────────

def _safe(detail: dict[str, Any] | None, key: str, default: Any = "") -> Any:
    if not detail or not isinstance(detail, dict):
        return default
    val = detail.get(key, default)
    return default if val is None else val


def _node_label(event: Event) -> str:
    """Pick the most readable node identifier from event detail / chr_id."""
    name = str(_safe(event.detail, "node_name") or _safe(event.detail, "node") or "")
    if name:
        return name
    if event.chr_id is not None:
        return f"chr#{event.chr_id}"
    return "—"


# ── per-kind rule functions ───────────────────────────────────────────────

def _rule_health_down(event: Event) -> AlertSpec:
    node = _node_label(event)
    latency = _safe(event.detail, "latency_ms")
    extra = f"آخر استجابة: {latency} ms" if latency not in (None, "") else "لا استجابة"
    body = (
        f"[فليت] العقدة «{node}» سقطت ({extra}).\n"
        "سيُحاول النظام تحويل الجلسات تلقائياً إذا كانت الإعدادات تسمح بذلك."
    )
    return AlertSpec(
        kind=event.kind, title=f"سقوط عقدة CHR: {node}",
        body=body,
        dedupe_key=f"chr:{event.chr_id}:health_down",
        severity="crit", default_enabled=True,
    )


def _rule_health_up(event: Event) -> AlertSpec:
    node = _node_label(event)
    body = f"[فليت] العقدة «{node}» عادت إلى الخدمة."
    return AlertSpec(
        kind=event.kind, title=f"عودة عقدة CHR: {node}",
        body=body,
        # Recovery is a transient edge — don't dedupe so each comeback fires
        # if the owner has the kind enabled. The same node bouncing up/down
        # is best surfaced by the next health_down anyway.
        dedupe_key=None,
        severity="info", default_enabled=False,
    )


def _rule_failover_start(event: Event) -> AlertSpec:
    node = _node_label(event)
    sessions = _safe(event.detail, "session_count", "?")
    body = (
        f"[فليت] بدء إخلاء العقدة «{node}» — جلسات قيد التحويل: {sessions}."
    )
    return AlertSpec(
        kind=event.kind, title=f"إخلاء عقدة: {node}",
        body=body,
        dedupe_key=f"chr:{event.chr_id}:failover",
        severity="warn", default_enabled=True,
    )


def _rule_failover_done(event: Event) -> AlertSpec:
    node = _node_label(event)
    moved = _safe(event.detail, "moved", _safe(event.detail, "session_count", "?"))
    failed = _safe(event.detail, "failed", 0)
    body = (
        f"[فليت] انتهى إخلاء «{node}». تم تحويل {moved} جلسة"
        + (f" — فشل {failed}." if failed not in (0, "0", "") else ".")
    )
    return AlertSpec(
        kind=event.kind, title=f"اكتمال إخلاء عقدة: {node}",
        body=body,
        # Pair with the failover_start dedupe slot so the storm guards close
        # together; once "done" lands, the slot clears.
        dedupe_key=f"chr:{event.chr_id}:failover_done",
        severity="info", default_enabled=True,
    )


def _rule_cap_warn(event: Event) -> AlertSpec:
    node = _node_label(event)
    pct = _safe(event.detail, "fill_pct", _safe(event.detail, "used_pct", "?"))
    body = f"[فليت] تحذير سعة: «{node}» وصلت إلى {pct}%."
    return AlertSpec(
        kind=event.kind, title=f"تحذير سعة: {node}",
        body=body,
        dedupe_key=f"chr:{event.chr_id}:cap_warn",
        severity="warn", default_enabled=True,
    )


def _rule_cap_breach(event: Event) -> AlertSpec:
    node = _node_label(event)
    pct = _safe(event.detail, "fill_pct", _safe(event.detail, "used_pct", "?"))
    body = (
        f"[فليت] تجاوز سعة: «{node}» — {pct}%. "
        "قد يبدأ النظام بإعادة التوزيع."
    )
    return AlertSpec(
        kind=event.kind, title=f"تجاوز سعة: {node}",
        body=body,
        dedupe_key=f"chr:{event.chr_id}:cap_breach",
        severity="crit", default_enabled=True,
    )


def _rule_dns_update(event: Event) -> AlertSpec:
    fqdn = _safe(event.detail, "fqdn", "")
    before = _safe(event.detail, "previous_ips", []) or []
    after = _safe(event.detail, "publish_ips", _safe(event.detail, "new_ips", [])) or []
    body = (
        f"[فليت/DNS] تحديث {fqdn}: عناوين قديمة {len(before)} → جديدة {len(after)}."
    )
    return AlertSpec(
        kind=event.kind, title=f"تحديث DNS: {fqdn}",
        body=body,
        # DNS updates are inherently noisy on a reconcile-every-N-seconds
        # loop; the producer already suppresses no-change cycles. We dedupe
        # by (fqdn, kind) so a flap inside one reconcile window collapses
        # to one alert; a real subsequent change opens a new slot once the
        # previous one is acked / cleared.
        dedupe_key=f"dns:{fqdn}:dns_update",
        severity="info", default_enabled=False,
    )


def _rule_dns_suppressed(event: Event) -> AlertSpec:
    fqdn = _safe(event.detail, "fqdn", "")
    reason = _safe(event.detail, "reason", "")
    body = (
        f"[فليت/DNS] تم منع تحديث {fqdn} (الحماية من فراغ السجل).\n"
        + (f"السبب: {reason}." if reason else "")
    )
    return AlertSpec(
        kind=event.kind, title=f"منع تحديث DNS: {fqdn}",
        body=body.strip(),
        dedupe_key=f"dns:{fqdn}:dns_suppressed",
        severity="warn", default_enabled=True,
    )


def _rule_move_ok(event: Event) -> AlertSpec:
    node = _node_label(event)
    user = _safe(event.detail, "user", "?")
    prev = _safe(event.detail, "previous_node", "")
    body = f"[فليت] تم تحويل المستخدم {user} → «{node}»" + (f" (من {prev})." if prev else ".")
    return AlertSpec(
        kind=event.kind, title=f"نقل ناجح: {user}",
        body=body,
        # No dedupe: each individual move success is a discrete event the
        # owner may or may not want. The owner will usually keep this OFF.
        dedupe_key=None,
        severity="info", default_enabled=False,
    )


def _rule_move_fail(event: Event) -> AlertSpec:
    node = _node_label(event)
    user = _safe(event.detail, "user", "?")
    reason = _safe(event.detail, "reason", "")
    body = (
        f"[فليت] فشل نقل المستخدم {user} إلى «{node}»."
        + (f" السبب: {reason}." if reason else "")
    )
    return AlertSpec(
        kind=event.kind, title=f"فشل نقل: {user}",
        # Per-user, per-node dedupe so a sticky failure doesn't spam — but
        # different (user,node) combos each get their own slot.
        body=body,
        dedupe_key=f"chr:{event.chr_id}:move_fail:{user}",
        severity="warn", default_enabled=True,
    )


def _rule_onboard_fail(event: Event) -> AlertSpec:
    node = _node_label(event)
    step = _safe(event.detail, "step", "")
    body = (
        f"[فليت] فشل إدخال عقدة CHR «{node}»"
        + (f" في خطوة {step}." if step else ".")
    )
    return AlertSpec(
        kind=event.kind, title=f"فشل إدخال عقدة: {node}",
        body=body,
        dedupe_key=f"chr:{event.chr_id}:onboard_fail",
        severity="warn", default_enabled=True,
    )


def _rule_onboard_ok(event: Event) -> AlertSpec:
    node = _node_label(event)
    body = f"[فليت] تم إدخال عقدة جديدة «{node}» بنجاح."
    return AlertSpec(
        kind=event.kind, title=f"عقدة جديدة جاهزة: {node}",
        body=body,
        dedupe_key=None,  # one-off success
        severity="info", default_enabled=False,
    )


def _rule_flap_suppressed(event: Event) -> AlertSpec:
    node = _node_label(event)
    body = (
        f"[فليت] تم كبح تحويلات «{node}» بسبب تذبذب الحالة."
    )
    return AlertSpec(
        kind=event.kind, title=f"كبح تذبذب: {node}",
        body=body,
        dedupe_key=f"chr:{event.chr_id}:flap_suppressed",
        severity="warn", default_enabled=True,
    )


def _rule_cost_cap_nearing(event: Event) -> AlertSpec:
    """Producer-agnostic placeholder for the cost-cap event kind.

    Phase-9 ships the rule + UI + dedupe so the producer (cost-tracking
    worker, separate phase) can drop a single Event row of this kind and
    have the alert flow already wired. The kind isn't in
    :data:`EVENT_KINDS` yet — the catalog is intentionally additive.
    """
    pct = _safe(event.detail, "used_pct", "?")
    cap = _safe(event.detail, "cap_label", "")
    body = (
        f"[فليت] التكلفة الشهرية وصلت إلى {pct}% من السقف"
        + (f" ({cap})." if cap else ".")
    )
    return AlertSpec(
        kind=event.kind, title="اقتراب سقف التكلفة",
        body=body,
        dedupe_key=f"fleet:cost_cap:nearing",
        severity="warn", default_enabled=True,
    )


#: Catalog: event kind → rule function. Producers can ship a new event
#: kind without breaking the notifier — :func:`spec_for` falls back to a
#: generic "unknown kind" alert that the operator can decide to silence.
_RULES: dict[str, Callable[[Event], AlertSpec]] = {
    "health_down":      _rule_health_down,
    "health_up":        _rule_health_up,
    "failover_start":   _rule_failover_start,
    "failover_done":    _rule_failover_done,
    "cap_warn":         _rule_cap_warn,
    "cap_breach":       _rule_cap_breach,
    "dns_update":       _rule_dns_update,
    "dns_suppressed":   _rule_dns_suppressed,
    "move_ok":          _rule_move_ok,
    "move_fail":        _rule_move_fail,
    "onboard_ok":       _rule_onboard_ok,
    "onboard_fail":     _rule_onboard_fail,
    "flap_suppressed":  _rule_flap_suppressed,
    # Additive: producer not in tree yet (separate cost worker phase). The
    # UI + rule + dedupe slot exist today so wiring is one line later.
    "cost_cap_nearing": _rule_cost_cap_nearing,
}


def spec_for(event: Event) -> AlertSpec:
    """Return the :class:`AlertSpec` for ``event``.

    Unknown kinds fall back to a generic ``info`` spec keyed on the kind so
    the matrix remains forward-compatible with producers that ship new
    event types ahead of the notifier's catalog update.
    """
    rule = _RULES.get(event.kind)
    if rule is not None:
        return rule(event)
    return AlertSpec(
        kind=event.kind, title=f"حدث: {event.kind}",
        body=f"[فليت] حدث {event.kind}.",
        dedupe_key=f"fleet:unknown:{event.kind}:{event.chr_id}",
        severity=(event.severity or "info"),
        default_enabled=False,
    )


#: Owner-facing catalog the settings UI iterates over. Pairs kind with a
#: short Arabic label so we don't depend on running the rule against a
#: dummy event just to read its title.
KIND_LABELS: dict[str, str] = {
    "health_down":      "سقوط عقدة (حرج)",
    "health_up":        "عودة عقدة للخدمة",
    "failover_start":   "بدء إخلاء عقدة",
    "failover_done":    "اكتمال إخلاء عقدة",
    "cap_warn":         "تحذير سعة",
    "cap_breach":       "تجاوز سعة (حرج)",
    "dns_update":       "تحديث DNS",
    "dns_suppressed":   "منع تحديث DNS",
    "move_ok":          "نقل مستخدم ناجح",
    "move_fail":        "فشل نقل مستخدم",
    "onboard_ok":       "إدخال عقدة جديدة",
    "onboard_fail":     "فشل إدخال عقدة",
    "flap_suppressed":  "كبح تذبذب عقدة",
    "cost_cap_nearing": "اقتراب سقف التكلفة",
}


#: Default ON/OFF per kind. The UI seeds the toggles from this when the
#: owner hasn't saved a preference yet.
KIND_DEFAULTS: dict[str, bool] = {
    "health_down":      True,
    "health_up":        False,
    "failover_start":   True,
    "failover_done":    True,
    "cap_warn":         True,
    "cap_breach":       True,
    "dns_update":       False,
    "dns_suppressed":   True,
    "move_ok":          False,
    "move_fail":        True,
    "onboard_ok":       False,
    "onboard_fail":     True,
    "flap_suppressed":  True,
    "cost_cap_nearing": True,
}


__all__ = ["AlertSpec", "KIND_DEFAULTS", "KIND_LABELS", "spec_for"]
