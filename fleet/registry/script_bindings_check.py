"""fleet.registry.script_bindings_check — verify a binding dict is real before
we hand the rendered ``.rsc`` to an operator.

Why this exists
---------------
The unified template (``chr_unified.rsc.j2``) contains many fields that are
**fleet-constant** — the panel's WireGuard control-plane pubkey/endpoint, the
central RADIUS proxy's WireGuard pubkey/endpoint, the shared RADIUS secret, and
the SSTP/IPsec TLS certificate names. None of these are per-CHR; they all come
from PANEL infrastructure that must be set up ONCE before any onboarding can
produce a workable RouterOS script.

Until those values are configured, the renderer happily substitutes empty
strings (its job is mechanical substitution, not policy). The result is
syntactically-broken RouterOS lines like::

    add interface=wg-mgmt public-key=""        ← RouterOS: expected end of command
        endpoint-address= endpoint-port=51820   ← endpoint-address has no value
    add service=ppp address=10.98.0.1 secret=""

The owner discovered this the hard way on his first real install.

Contract
--------
``check_bindings(bindings) -> list[MissingBinding]`` walks the dict produced
by ``OnboardingService._build_bindings`` (or
``fleet.registry.script_render.build_bindings``) and returns one entry per
critical field that is empty, ``None``, or still a literal placeholder
(``"<…>"``). Empty list = ready to ship.

The list is ORDERED roughly by setup phase (panel control-plane, proxy
control-plane, RADIUS secret, cert) so the operator-facing message can read
naturally without our caller doing extra work.

What this module deliberately does NOT do
-----------------------------------------
* It does NOT validate the per-CHR private keys deeply. The WG private keys
  are sourced from the vault and the renderer only sees their plaintext;
  an empty WG private key means key generation failed — a separate failure
  mode caught earlier. We still flag it (defence in depth) so an
  end-to-end render-and-serve flow always refuses to present a broken
  script, regardless of how it got broken.
* It does NOT touch the DB or the vault. Pure function over a dict.
* It does NOT short-circuit on the first missing item; the operator wants
  to see EVERYTHING that's blocking onboarding, not fix one at a time.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MissingBinding:
    """One missing binding the operator needs to action.

    ``key`` is the template variable name (so future log/audit can search by
    key). ``label_ar`` is the human-facing reason the operator sees on the
    pending card. ``setup_hint_ar`` says WHERE the value should come from.
    """

    key: str
    label_ar: str
    setup_hint_ar: str


# Critical bindings the rendered script absolutely needs to be installable on
# a real CHR. If any of these are empty/placeholder, the .rsc is broken.
# Order is the natural setup phase: panel control-plane → proxy data-plane →
# RADIUS secret → per-CHR keys.
_CRITICAL_BINDINGS: tuple[tuple[str, str, str], ...] = (
    # ── Panel control-plane (wg-mgmt) ────────────────────────────────────
    ("PANEL_WG_PUBKEY",
     "مفتاح اللوحة العام (WireGuard control-plane)",
     "يأتي من إعداد خادم wg-mgmt على اللوحة. أنشئ زوج المفاتيح + سجّل المفتاح "
     "العام هنا حتى تستطيع العقدة تصافحه."),
    ("PANEL_WG_ENDPOINT",
     "نقطة وصول اللوحة (Host:Port للـ control-plane)",
     "العنوان العام للوحة (FQDN أو IP) على المنفذ 51820 الذي تتصل به العقد "
     "عبر wg-mgmt. لا بد أن يكون قابلاً للوصول من الإنترنت."),
    # ── Proxy data-plane (wg-data) ───────────────────────────────────────
    ("PROXY_WG_PUBKEY",
     "مفتاح وكيل RADIUS المركزي العام (WireGuard data-plane)",
     "ينشر وكيل RADIUS مفتاحه العام؛ يُسجَّل هنا حتى تتصافح العقد معه عبر wg-data."),
    ("PROXY_WG_ENDPOINT",
     "نقطة وصول وكيل RADIUS (Host:Port للـ data-plane)",
     "العنوان العام لوكيل RADIUS المركزي على المنفذ 51821."),
    # ── Shared RADIUS secret ─────────────────────────────────────────────
    ("CHR_SHARED_SECRET",
     "السر المشترك لـ RADIUS بين العقدة والوكيل",
     "يُضبط مرة واحدة على الأسطول؛ نفسه على كل CHR ووكيل. خزّنه مُشفَّراً في "
     "إعدادات اللوحة."),
    # ── Per-CHR keys (defence in depth) ──────────────────────────────────
    ("WG_MGMT_PRIVKEY",
     "مفتاح wg-mgmt الخاص للعقدة",
     "يُولِّده اللوحة عند المرحلة «توليد المفاتيح»؛ يُخزَّن مشفّراً في خزنة "
     "الأسرار. إن كان فارغاً فهذا يعني أن خطوة التوليد فشلت — استخدم «إعادة المحاولة»."),
    ("WG_DATA_PRIVKEY",
     "مفتاح wg-data الخاص للعقدة",
     "يُولِّده اللوحة عند المرحلة «توليد المفاتيح»؛ يُخزَّن مشفّراً في خزنة الأسرار."),
)


def _is_empty(value) -> bool:
    """``True`` if ``value`` is unusable as a RouterOS binding.

    Treats ``None``, empty string, whitespace-only, and the
    ``"<PLACEHOLDER>"`` shape from the documentation-defaults dataclass all
    as missing. (The defaults in ``_FLEET_CONST_DEFAULTS`` are ``""`` so the
    placeholder case is mainly there as belt-and-braces for the
    ``RouterosTemplateConfig`` dataclass defaults.)
    """
    if value is None:
        return True
    s = str(value).strip()
    if not s:
        return True
    if s.startswith("<") and s.endswith(">"):
        return True
    return False


def check_bindings(bindings: dict) -> list[MissingBinding]:
    """Return the ordered list of missing critical bindings.

    Empty list → the .rsc is ready to be installed on a real CHR.
    """
    missing: list[MissingBinding] = []
    for key, label_ar, setup_hint_ar in _CRITICAL_BINDINGS:
        if _is_empty(bindings.get(key)):
            missing.append(MissingBinding(key=key, label_ar=label_ar,
                                          setup_hint_ar=setup_hint_ar))
    return missing


def summary_ar(missing: list[MissingBinding]) -> str:
    """Compose a single Arabic line listing every missing binding.

    Format::

        "بانتظار إعداد: <label1>؛ <label2>؛ … (راجع إعدادات بنية اللوحة)"
    """
    if not missing:
        return ""
    labels = "؛ ".join(m.label_ar for m in missing)
    return f"بانتظار إعداد: {labels} (راجع إعدادات بنية اللوحة)."


__all__ = [
    "MissingBinding",
    "check_bindings",
    "summary_ar",
]
