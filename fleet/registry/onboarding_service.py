"""fleet.registry.onboarding_service — CHR auto-onboarding wizard state machine.

Phase 3 / P3-T1. Drives one CHR from a submitted wizard form through:

    draft → keys_generated → script_generated → pushed
                                                   ↘ failed → script_generated (retry)

per docs/chr_fleet/06_ONBOARDING_WIZARD.md §6.2. The ``verifying → active``
promotion runs after the post-push health checks (§6.7) which belong to the
monitoring phase; T1 owns the build-and-push half.

Collaborators (owned by sibling Phase-3 tasks, called via the interfaces below —
NOT reimplemented here):

  * P3-T2 ``fleet.registry.wg_keys``        → :class:`KeyProvider`
  * P3-T2 ``fleet.registry.secrets_vault``  → :class:`SecretsVault`
  * P3-T3 ``fleet.registry.script_render``  → :class:`ScriptRenderer`
  * P3-T4 ``fleet.registry.bootstrap_push`` → :class:`BootstrapPusher`

Those modules do not exist on ``main`` yet, so they are **injected** (constructor
args) and the defaults **lazy-import** the real module on first use. This keeps
``import app`` clean today and lets the unit tests drive the full state machine
with in-memory fakes. When the sibling tasks land, the defaults pick them up with
zero changes here.

Secret-handling invariant (carried from §6.3 / 02 §2.10): WireGuard PRIVATE keys
and the rendered script (which embeds them) are NEVER stored as plaintext columns.
Private keys live in the vault by reference; the script is re-rendered server-side
at push time from those refs and never returned to the browser.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.extensions import db
from app.models import utcnow
from fleet.registry import provider_service
from fleet.registry.models_chr import FleetChrNode
from fleet.registry.models_onboarding import OnboardingJob


# ──────────────────────────────────────────────────────────────────────────────
# Errors
# ──────────────────────────────────────────────────────────────────────────────
class OnboardingError(ValueError):
    """Base onboarding error (bad form, illegal transition, push failure)."""


class OnboardingDependencyError(RuntimeError):
    """A required Phase-3 collaborator module is not available yet."""


# ──────────────────────────────────────────────────────────────────────────────
# Collaborator interfaces (frozen shapes the sibling tasks implement)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class WgKeyPair:
    """A WireGuard keypair. The private key is a SECRET — vault it, never log it."""

    private_key: str
    public_key: str


@dataclass(frozen=True)
class PushResult:
    """Outcome of delivering+running the script over the one-time channel."""

    ok: bool
    detail: str = ""


@runtime_checkable
class KeyProvider(Protocol):
    """P3-T2 fleet.registry.wg_keys."""

    def generate_keypair(self) -> WgKeyPair: ...


@runtime_checkable
class SecretsVault(Protocol):
    """P3-T2 fleet.registry.secrets_vault — stores secrets by opaque reference."""

    def store_secret(self, hint: str, secret: str) -> str: ...

    def fetch_secret(self, ref: str) -> str: ...


@runtime_checkable
class ScriptRenderer(Protocol):
    """P3-T3 fleet.registry.script_render — renders the unified RouterOS script."""

    def render(self, bindings: dict[str, Any]) -> str: ...


@runtime_checkable
class BootstrapPusher(Protocol):
    """P3-T4 fleet.registry.bootstrap_push — delivers+runs the script once."""

    def push(self, reach: dict[str, Any], script: str) -> PushResult: ...


# ──────────────────────────────────────────────────────────────────────────────
# Wizard form (§6.1)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class WizardForm:
    """The only human input. Mirrors docs/chr_fleet/06 §6.1."""

    provider: str
    name: str
    public_ip: str
    cost_model: str
    max_sessions: int
    link_speed_mbps: int
    public_ipv6: str | None = None
    monthly_cap_tb: float | None = None
    overage_allowed: bool = False
    price_per_tb: float | None = None
    weight: float = 1.0
    # Optional explicit control-plane address; otherwise allocated from the
    # fleet wg-mgmt pool (see OnboardingService._allocate_mgmt_ip).
    wg_mgmt_ip: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WizardForm":
        if not isinstance(data, dict):
            raise OnboardingError("نموذج التسجيل غير صالح.")

        def _req_str(key: str) -> str:
            val = str(data.get(key) or "").strip()
            if not val:
                raise OnboardingError(f"الحقل «{key}» مطلوب.")
            return val

        def _req_int(key: str) -> int:
            try:
                val = int(data.get(key))
            except (TypeError, ValueError) as exc:
                raise OnboardingError(f"الحقل «{key}» يجب أن يكون عدداً صحيحاً.") from exc
            if val <= 0:
                raise OnboardingError(f"الحقل «{key}» يجب أن يكون موجباً.")
            return val

        cost_model = _req_str("cost_model").lower()
        if cost_model not in ("open", "metered"):
            raise OnboardingError("نموذج التكلفة يجب أن يكون open أو metered.")

        return cls(
            provider=_req_str("provider"),
            name=_req_str("name"),
            public_ip=_req_str("public_ip"),
            cost_model=cost_model,
            max_sessions=_req_int("max_sessions"),
            link_speed_mbps=_req_int("link_speed_mbps"),
            public_ipv6=(str(data.get("public_ipv6")).strip() or None) if data.get("public_ipv6") else None,
            monthly_cap_tb=data.get("monthly_cap_tb"),
            overage_allowed=bool(data.get("overage_allowed", False)),
            price_per_tb=data.get("price_per_tb"),
            weight=float(data.get("weight") or 1.0),
            wg_mgmt_ip=(str(data.get("wg_mgmt_ip")).strip() or None) if data.get("wg_mgmt_ip") else None,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "name": self.name,
            "public_ip": self.public_ip,
            "public_ipv6": self.public_ipv6,
            "cost_model": self.cost_model,
            "max_sessions": self.max_sessions,
            "link_speed_mbps": self.link_speed_mbps,
            "monthly_cap_tb": self.monthly_cap_tb,
            "overage_allowed": self.overage_allowed,
            "price_per_tb": self.price_per_tb,
            "weight": self.weight,
            "wg_mgmt_ip": self.wg_mgmt_ip,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Lazy default collaborators (resolve the real Phase-3 modules when present)
# ──────────────────────────────────────────────────────────────────────────────
def _lazy(module_path: str, attr: str, what: str):
    try:
        import importlib

        mod = importlib.import_module(module_path)
    except ImportError as exc:  # sibling task not merged yet
        raise OnboardingDependencyError(
            f"{what} غير متوفر بعد (الوحدة {module_path} من مهمة Phase-3 أخرى). "
            f"مرّر بديلاً عبر الحقن في الاختبارات."
        ) from exc
    obj = getattr(mod, attr, None)
    if obj is None:
        raise OnboardingDependencyError(f"{module_path}.{attr} غير معرّف.")
    return obj


class _DefaultKeyProvider:
    def generate_keypair(self) -> WgKeyPair:
        gen = _lazy("fleet.registry.wg_keys", "generate_keypair", "مولّد مفاتيح WireGuard")
        priv, pub = gen()
        return WgKeyPair(private_key=priv, public_key=pub)


class _DefaultVault:
    def store_secret(self, hint: str, secret: str) -> str:
        store = _lazy("fleet.registry.secrets_vault", "store_secret", "خزنة الأسرار")
        return store(hint, secret)

    def fetch_secret(self, ref: str) -> str:
        fetch = _lazy("fleet.registry.secrets_vault", "fetch_secret", "خزنة الأسرار")
        return fetch(ref)


class _DefaultRenderer:
    def render(self, bindings: dict[str, Any]) -> str:
        render = _lazy("fleet.registry.script_render", "render", "مُولّد سكربت RouterOS")
        return render(bindings)


class _DefaultPusher:
    def push(self, reach: dict[str, Any], script: str) -> PushResult:
        push = _lazy("fleet.registry.bootstrap_push", "push", "ناقل الإقلاع")
        res = push(reach, script)
        # Tolerate either a PushResult or a (ok, detail) tuple from the real impl.
        if isinstance(res, PushResult):
            return res
        ok, detail = (res if isinstance(res, tuple) else (bool(res), ""))
        return PushResult(ok=bool(ok), detail=str(detail))


# ──────────────────────────────────────────────────────────────────────────────
# The service
# ──────────────────────────────────────────────────────────────────────────────
# Fleet-CONSTANT binding defaults (§6.5.1). Overridable via app config keys of the
# same name; the per-CHR bindings come from the node/keys, not from here.
_FLEET_CONST_DEFAULTS: dict[str, Any] = {
    "PANEL_WG_PUBKEY": "",
    "PANEL_WG_ENDPOINT": "",
    "PANEL_WG_ADDR": "10.99.0.1",
    "PROXY_WG_PUBKEY": "",
    "PROXY_WG_ENDPOINT": "",
    "PROXY_WG_ADDR": "10.98.0.1",
    "CHR_SHARED_SECRET": "",
    "SSTP_CERT_NAME": "vpn-hoberadius",
    "IKE_CERT_NAME": "vpn-hoberadius",
    "CLIENT_SUPERNET": "10.0.0.0/8",
    "DNS_PUSH": "1.1.1.1",
    "GW_LOCAL_ADDR": "10.255.255.1",
    "WAN_IFACE": "ether1",
}

# Pool the wg-mgmt control-plane addresses are allocated from (§6.3).
_WG_MGMT_POOL_PREFIX = "10.99.0."
_WG_MGMT_POOL_START = 11  # .1 is the panel; nodes start at .11


@dataclass
class OnboardingService:
    """Stateless orchestrator (collaborators injected). One instance per request
    is fine; it holds no per-job state."""

    key_provider: KeyProvider = field(default_factory=_DefaultKeyProvider)
    vault: SecretsVault = field(default_factory=_DefaultVault)
    renderer: ScriptRenderer = field(default_factory=_DefaultRenderer)
    pusher: BootstrapPusher = field(default_factory=_DefaultPusher)
    config: dict[str, Any] | None = None

    # ── config access (works in or out of an app context) ────────────────────
    def _const(self, key: str) -> Any:
        if self.config is not None and key in self.config:
            return self.config[key]
        try:
            from flask import current_app

            if current_app:
                val = current_app.config.get(key)
                if val is not None:
                    return val
        except Exception:
            pass
        return _FLEET_CONST_DEFAULTS.get(key, "")

    # ── step 0: draft ────────────────────────────────────────────────────────
    def create_draft(self, form: WizardForm | dict[str, Any]) -> OnboardingJob:
        """Submit the wizard form → a ``draft`` job. Resolves/creates the provider."""
        if isinstance(form, dict):
            form = WizardForm.from_dict(form)
        # Resolve or create the provider (the "select/new" field, §6.1).
        provider_service.upsert_provider_by_name(
            form.provider,
            cost_model=form.cost_model,
            price_per_tb=form.price_per_tb or 0,
            monthly_cap_tb=form.monthly_cap_tb,
            overage_allowed=form.overage_allowed,
        )
        job = OnboardingJob(status="draft")
        job.form_input = form.to_json()
        db.session.add(job)
        db.session.commit()
        return job

    # ── step 1: keys_generated ───────────────────────────────────────────────
    def generate_keys(self, job: OnboardingJob) -> OnboardingJob:
        """Make the wg-mgmt + wg-data keypairs, vault the private keys, and create
        the ``fleet_chr_nodes`` row carrying the mgmt PUBLIC key. → keys_generated."""
        self._require(job, "keys_generated")
        form = WizardForm.from_dict(job.form_input)

        mgmt = self.key_provider.generate_keypair()
        data = self.key_provider.generate_keypair()
        mgmt_ref = self.vault.store_secret(f"chr/{form.name}/wg-mgmt-privkey", mgmt.private_key)
        data_ref = self.vault.store_secret(f"chr/{form.name}/wg-data-privkey", data.private_key)

        provider = provider_service.get_provider_by_name(form.provider)
        if provider is None:  # defensive: draft created it
            raise OnboardingError("تعذّر إيجاد المزوّد للعقدة.")

        node = FleetChrNode(
            provider_id=provider.id,
            name=form.name,
            public_ip=form.public_ip,
            public_ipv6=form.public_ipv6,
            wg_mgmt_ip=form.wg_mgmt_ip or self._allocate_mgmt_ip(),
            wg_mgmt_pubkey=mgmt.public_key,
            max_sessions=form.max_sessions,
            link_speed_mbps=form.link_speed_mbps,
            weight=form.weight,
            status="provisioning",
        )
        db.session.add(node)
        db.session.flush()  # assign node.id for the FK below

        job.chr_id = node.id
        # Store vault REFERENCES (never the private keys) + the non-secret pubkeys.
        job.wg_keypair_ref = json.dumps({
            "mgmt_privkey_ref": mgmt_ref,
            "data_privkey_ref": data_ref,
            "mgmt_pubkey": mgmt.public_key,
            "data_pubkey": data.public_key,
        })
        job.advance("keys_generated")
        db.session.commit()
        return job

    # ── step 2: script_generated ─────────────────────────────────────────────
    def render_script(self, job: OnboardingJob) -> tuple[OnboardingJob, str]:
        """Render the unified RouterOS script for this node. → script_generated.

        Returns the script for the caller, but persists only a content hash as
        ``generated_script_ref`` (the script embeds private keys — never stored).
        """
        self._require(job, "script_generated")
        script = self.renderer.render(self._build_bindings(job))
        job.generated_script_ref = "sha256:" + hashlib.sha256(script.encode("utf-8")).hexdigest()
        job.advance("script_generated")
        db.session.commit()
        return job, script

    # ── step 3: pushed ───────────────────────────────────────────────────────
    def push(
        self,
        job: OnboardingJob,
        reach: dict[str, Any],
        *,
        script: str | None = None,
    ) -> OnboardingJob:
        """Deliver+run the script over the one-time channel. → pushed (or failed).

        If ``script`` is None the script is re-rendered server-side from the vault
        refs (so the secret-bearing script never has to travel back through HTTP).
        """
        self._require(job, "pushed")
        if script is None:
            script = self.renderer.render(self._build_bindings(job))
        result = self.pusher.push(reach, script)
        if not result.ok:
            self.mark_failed(job, result.detail or "فشل دفع السكربت إلى العقدة.")
            raise OnboardingError(result.detail or "فشل دفع السكربت إلى العقدة.")
        job.advance("pushed")
        db.session.commit()
        return job

    # ── failure / retry ──────────────────────────────────────────────────────
    def mark_failed(self, job: OnboardingJob, reason: str) -> OnboardingJob:
        """Move the job to ``failed`` and record why (idempotent-friendly)."""
        if job.status != "failed":
            job.advance("failed")
        job.verify_report = {"failed_reason": reason, "at": utcnow().isoformat()}
        db.session.commit()
        return job

    def retry(self, job: OnboardingJob) -> OnboardingJob:
        """``failed → script_generated`` retry edge (§6.2)."""
        job.advance("script_generated")
        db.session.commit()
        return job

    # ── convenience pipeline ─────────────────────────────────────────────────
    def provision(self, form: WizardForm | dict[str, Any], reach: dict[str, Any]) -> OnboardingJob:
        """Run the whole happy path draft→…→pushed in one call (server-side)."""
        job = self.create_draft(form)
        self.generate_keys(job)
        _, script = self.render_script(job)
        return self.push(job, reach, script=script)

    # ── helpers ──────────────────────────────────────────────────────────────
    def _require(self, job: OnboardingJob, target: str) -> None:
        if not job.can_advance_to(target):
            raise OnboardingError(
                f"انتقال غير مسموح: {job.status!r} → {target!r}."
            )

    def _allocate_mgmt_ip(self) -> str:
        """Next free address in the wg-mgmt pool (10.99.0.11+). Scans existing nodes."""
        used = {
            ip for (ip,) in db.session.query(FleetChrNode.wg_mgmt_ip).all() if ip
        }
        for octet in range(_WG_MGMT_POOL_START, 255):
            candidate = f"{_WG_MGMT_POOL_PREFIX}{octet}"
            if candidate not in used:
                return candidate
        raise OnboardingError("نفد مجال عناوين wg-mgmt (10.99.0.0/24).")

    def _build_bindings(self, job: OnboardingJob) -> dict[str, Any]:
        """Merge per-CHR bindings (from the node + vaulted keys) with the
        fleet-constant config (§6.5.1). The renderer (T3) owns the template."""
        if not job.chr_id:
            raise OnboardingError("لا يمكن توليد السكربت قبل إنشاء عقدة CHR.")
        node = db.session.get(FleetChrNode, job.chr_id)
        if node is None:
            raise OnboardingError("عقدة CHR المرتبطة غير موجودة.")
        refs = json.loads(job.wg_keypair_ref or "{}")
        mgmt_priv = self.vault.fetch_secret(refs["mgmt_privkey_ref"]) if refs.get("mgmt_privkey_ref") else ""
        data_priv = self.vault.fetch_secret(refs["data_privkey_ref"]) if refs.get("data_privkey_ref") else ""

        bindings: dict[str, Any] = {
            # per-CHR (the only values that differ between CHRs)
            "ROUTER_IDENTITY": node.name,
            "CHR_PUBLIC_IP": node.public_ip,
            "WG_MGMT_PRIVKEY": mgmt_priv,
            "WG_MGMT_ADDR": f"{node.wg_mgmt_ip}/32",
            "WG_DATA_PRIVKEY": data_priv,
        }
        # fleet-constant
        for key in _FLEET_CONST_DEFAULTS:
            bindings[key] = self._const(key)
        return bindings


def job_to_dict(job: OnboardingJob) -> dict[str, Any]:
    """JSON-safe view of a job for the route layer (no secrets)."""
    return {
        "id": job.id,
        "status": job.status,
        "chr_id": job.chr_id,
        "form_input": job.form_input,
        "has_keys": bool(job.wg_keypair_ref),
        "script_ref": job.generated_script_ref,
        "verify_report": job.verify_report,
    }


__all__ = [
    "OnboardingService",
    "OnboardingError",
    "OnboardingDependencyError",
    "WizardForm",
    "WgKeyPair",
    "PushResult",
    "KeyProvider",
    "SecretsVault",
    "ScriptRenderer",
    "BootstrapPusher",
    "job_to_dict",
]
