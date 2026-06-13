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
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

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
    """P3-T4 fleet.registry.bootstrap_push — delivers+runs the script once.

    The real implementation (bootstrap_push.push_to_chr) also advances the job's
    status to 'pushed'/'failed' and commits; OnboardingService.push tolerates that
    via a conditional advance.
    """

    def push(self, job: "OnboardingJob", reach: dict[str, Any], script: str) -> PushResult: ...


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

        # Node-level cost model allows 'inherit' (use the provider's) in addition
        # to open/metered — matches FleetChrNode.cost_model and the wizard UI,
        # which defaults the node to 'inherit'.
        cost_model = _req_str("cost_model").lower()
        if cost_model not in ("inherit", "open", "metered"):
            raise OnboardingError("نموذج التكلفة يجب أن يكون inherit أو open أو metered.")

        # The wizard JS sends the node bandwidth cap as 'bandwidth_cap_tb'; accept
        # it as an alias for monthly_cap_tb.
        cap = data.get("monthly_cap_tb")
        if cap is None:
            cap = data.get("bandwidth_cap_tb")

        # Provider resolution — accept BOTH shapes so the wizard's natural
        # ``provider_id`` (from the dropdown) works AND a name-only payload
        # (the legacy/tests path) still works.
        #
        # The owner's repro shipped only ``provider_id`` and the old code
        # required ``provider`` (name) → hard-failed with
        # «الحقل «provider» مطلوب.» before any business logic ran. We now
        # resolve in this priority:
        #   1. ``provider`` (name)        — backward-compatible
        #   2. ``provider_id`` (int)      — looked up in fleet_providers
        # If neither yields a usable name, raise a precise Arabic message
        # (no opaque ``onboarding_error`` ever again).
        provider_name = str(data.get("provider") or "").strip()
        if not provider_name:
            raw_id = data.get("provider_id")
            if raw_id not in (None, "", "__new__"):
                try:
                    pid = int(raw_id)
                except (TypeError, ValueError) as exc:
                    raise OnboardingError(
                        "معرّف المزوّد (provider_id) يجب أن يكون رقماً."
                    ) from exc
                from fleet.registry.models_chr import FleetProvider  # local import
                prov = db.session.get(FleetProvider, pid)
                if prov is None:
                    raise OnboardingError(
                        f"لا يوجد مزوّد بالمعرّف {pid}. اختر مزوّداً من القائمة."
                    )
                provider_name = prov.name
        if not provider_name:
            raise OnboardingError(
                "اختر المزوّد من القائمة قبل المتابعة (provider أو provider_id مطلوب)."
            )

        return cls(
            provider=provider_name,
            name=_req_str("name"),
            public_ip=_req_str("public_ip"),
            cost_model=cost_model,
            max_sessions=_req_int("max_sessions"),
            link_speed_mbps=_req_int("link_speed_mbps"),
            public_ipv6=(str(data.get("public_ipv6")).strip() or None) if data.get("public_ipv6") else None,
            monthly_cap_tb=cap,
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
        kp = gen()  # fleet.registry.wg_keys.WgKeypair (frozen, .private_key/.public_key)
        return WgKeyPair(private_key=kp.private_key, public_key=kp.public_key)


class _DefaultVault:
    def store_secret(self, hint: str, secret: str) -> str:
        # Real API is keyword-only store_secret(owner, purpose, plaintext, kind)
        # returning a VaultRef; we surface its opaque string for the VARCHAR ref.
        store = _lazy("fleet.registry.secrets_vault", "store_secret", "خزنة الأسرار")
        ref = store(owner=hint, purpose="onboarding", plaintext=secret, kind="wg_privkey")
        return str(ref)

    def fetch_secret(self, ref: str) -> str:
        # Real API names the read 'retrieve_secret'.
        retrieve = _lazy("fleet.registry.secrets_vault", "retrieve_secret", "خزنة الأسرار")
        return retrieve(ref)


class _DefaultRenderer:
    def render(self, bindings: dict[str, Any]) -> str:
        # Real API is render_from_bindings(bindings); its Jinja env uses
        # StrictUndefined, so _build_bindings must supply every template var (it does).
        render = _lazy("fleet.registry.script_render", "render_from_bindings", "مُولّد سكربت RouterOS")
        return render(bindings)


class _DefaultPusher:
    def push(self, job: OnboardingJob, reach: dict[str, Any], script: str) -> PushResult:
        # Real API is push_to_chr(job, BootstrapTarget, script). It ALSO advances
        # the job to pushed/failed and commits; OnboardingService.push tolerates
        # that with a conditional advance.
        push_to_chr = _lazy("fleet.registry.bootstrap_push", "push_to_chr", "ناقل الإقلاع")
        target_cls = _lazy("fleet.registry.bootstrap_push", "BootstrapTarget", "هدف الإقلاع")
        reach = reach or {}
        if not reach.get("host"):
            raise OnboardingError("دفع السكربت يتطلب عنوان الوصول (host) للعقدة.")
        target = target_cls(
            host=str(reach["host"]),
            port=int(reach.get("port", 8729)),
            username=str(reach.get("username", "admin")),
            password=str(reach.get("password", "")),
            transport_kind=str(reach.get("transport_kind", "api")),
        )
        res = push_to_chr(job, target, script)
        return PushResult(
            ok=bool(res.ok),
            detail=(getattr(res, "error", "") or getattr(res, "raw_output", "")),
        )


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
    # SSTP/IKE certs default to EMPTY — the unified template skips the
    # cert-bound server blocks when these are unset (fix/fleet-script-real-
    # bindings). Setting them implies the matching /certificate row is
    # already imported on every CHR; until that's true, leaving them blank
    # produces a script that installs cleanly without exposing dangling
    # ports for protocols whose certs aren't ready.
    "SSTP_CERT_NAME": "",
    "IKE_CERT_NAME": "",
    "CLIENT_SUPERNET": "10.0.0.0/8",
    "DNS_PUSH": "1.1.1.1",
    "GW_LOCAL_ADDR": "10.255.255.1",
    "WAN_IFACE": "ether1",
    # Panel-side read-only RouterOS API user (live-metrics poller).
    # When ``API_USER`` AND ``API_PASSWORD`` are BOTH non-empty the unified
    # script provisions a ``read``-group user reachable only over wg-mgmt
    # (the api-ssl service is bound to the management address; api on
    # 8728 stays off). When either is empty the script SKIPS the block —
    # the panel just won't have control-plane metrics until the operator
    # sets these in «إعدادات بنية الأسطول».
    "API_USER": "",
    "API_PASSWORD": "",
    "API_PORT": 8443,
    # feat/chr-auto-scoped-mgmt-user — dedicated SCOPED management user
    # group. The unified script's §11 creates this group with exactly the
    # policies the panel needs and binds the panel user to it:
    #
    #   read        — system_resource, /interface, /ppp/active, etc.
    #   write       — PUT/PATCH on /ppp/{secret,profile}, /ip/pool,
    #                 /ip/ipsec/*, /interface/wireguard{,/peers}
    #   sensitive   — required to write ppp/secret password=, ipsec PSK,
    #                 wireguard peer private-key=
    #   reboot      — /system/reboot from the CHR console
    #   rest-api    — the only login channel the panel uses
    #
    # Explicitly NOT granted: api (binary), ssh, winbox, ftp, web,
    # password (no user-mgmt), policy (no /system/scripts), sniff,
    # test, romon, dude, tikapp.
    "API_GROUP": "hobe-fleet-mgmt",
    # ── shared client pool + PPP profile (feat/chr-unified-provisioning-
    # complete). Same name + ranges on every node so a subscriber roaming
    # between CHRs keeps the same Framed-IP and the same profile (§10.2).
    "IP_POOL_NAME": "hobe-fleet-pool",
    "IP_POOL_RANGES": "10.50.0.10-10.50.255.254",
    "PPP_PROFILE_NAME": "hobe-fleet-default",
    # ── user-WireGuard listener (role: vpn_wireguard) ──────────────────
    # 51822 chosen to avoid collision with wg-mgmt 51820 / wg-data 51821.
    "WG_USERS_PORT": 51822,
    "WG_USERS_ADDR": "10.51.0.1/24",
    # ── self-lockout rollback window (§0a / §12 in the template) ──────
    "SAFEMODE_ROLLBACK_DELAY": "3m",
}

# Pool the wg-mgmt control-plane addresses are allocated from (§6.3).
_WG_MGMT_POOL_PREFIX = "10.99.0."
_WG_MGMT_POOL_START = 11  # .1 is the panel; nodes start at .11
# wg-data addresses parallel the wg-mgmt pool (same host octet) in 10.98.0.0/24.
_WG_DATA_POOL_PREFIX = "10.98.0."


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
        """Resolve a fleet-constant by template-var name.

        Chain: ``self.config`` (test injection) → ``Setting`` row → app config
        → built-in defaults. The Setting layer lands here so the new
        «إعدادات بنية الأسطول» page (feat/fleet-infrastructure-settings) can
        write the live values without any code change to the renderer — the
        validator's «بانتظار» clears the moment Setting rows exist.

        Secrets stored in the Setting layer are Fernet-encrypted; the
        settings_store module decrypts them on read. Non-secret fields
        (pubkeys, endpoints, cert names) are stored verbatim.
        """
        if self.config is not None and key in self.config:
            return self.config[key]
        # Setting layer (UI-managed) — feat/fleet-infrastructure-settings.
        try:
            from fleet.registry.infra_settings import get_fleet_const  # local import — avoids cycle at module load
            val = get_fleet_const(key)
            if val is not None and val != "":
                return val
        except Exception:  # noqa: BLE001 — never break render on a settings probe error
            pass
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
    def create_draft(
        self, form: WizardForm | dict[str, Any], *, auto_advance: bool = True,
    ) -> OnboardingJob:
        """Submit the wizard form → a job + (best-effort) a provisioning node.

        Behaviour (fix/fleet-onboarding-visibility):

        1. **Dedupe** by ``(provider, name)``. If a ``FleetChrNode`` already
           exists at that key OR an in-flight ``OnboardingJob`` (anything
           other than terminal ``active``/``failed``) names the same node,
           refuse with a precise Arabic message. This kills the "owner
           submitted the same form 3 times" silent duplicate spam.
        2. Resolve/upsert the provider (§6.1).
        3. Persist the ``draft`` job.
        4. **Auto-advance to ``keys_generated``** in the same request — this
           creates the ``fleet_chr_nodes`` row (``status='provisioning'``)
           so the operator SEES the node on the dashboard immediately. If
           the key generation fails (e.g. the panel vault key isn't set),
           the draft job remains in ``draft`` with a stamped
           ``form_input.last_error``; the pending-onboardings card on the
           dashboard surfaces it so nothing is invisible.
        """
        if isinstance(form, dict):
            form = WizardForm.from_dict(form)

        # ── 1. Dedupe ────────────────────────────────────────────────────
        provider_name = (form.provider or "").strip()
        node_name = (form.name or "").strip()
        existing_provider = provider_service.get_provider_by_name(provider_name)
        if existing_provider is not None:
            dup_node = FleetChrNode.query.filter_by(
                provider_id=existing_provider.id, name=node_name
            ).first()
            if dup_node is not None:
                raise OnboardingError(
                    f"عقدة باسم «{node_name}» موجودة مسبقاً على المزوّد «{provider_name}». "
                    f"اختر اسماً مختلفاً أو عدّل العقدة القائمة."
                )
        # Block parallel in-flight jobs for the same (provider, name).
        active_states = ("draft", "keys_generated", "script_generated", "pushed", "verifying")
        for j in OnboardingJob.query.filter(OnboardingJob.status.in_(active_states)).all():
            f = j.form_input or {}
            if (f.get("name") or "").strip() == node_name and (f.get("provider") or "").strip() == provider_name:
                raise OnboardingError(
                    f"يوجد عملية إعداد جارية للعقدة «{node_name}» على «{provider_name}» "
                    f"(الحالة: {j.status}). أكمل العملية الحالية أو احذفها قبل البدء من جديد."
                )

        # ── 2. Provider upsert ───────────────────────────────────────────
        provider_cost_model = form.cost_model if form.cost_model in ("open", "metered") else "open"
        provider_service.upsert_provider_by_name(
            form.provider,
            cost_model=provider_cost_model,
            price_per_tb=form.price_per_tb or 0,
            monthly_cap_tb=form.monthly_cap_tb,
            overage_allowed=form.overage_allowed,
        )

        # ── 3. Persist the draft job ─────────────────────────────────────
        job = OnboardingJob(status="draft")
        job.form_input = form.to_json()
        db.session.add(job)
        db.session.commit()

        # ── 4. Auto-advance to keys_generated (creates FleetChrNode) ─────
        # On by default so the submit route makes the node visible immediately.
        # Internal callers (provision) and stepwise tests pass auto_advance=False
        # to keep the clean draft → generate_keys → … state machine. Wrapped so a
        # missing/misconfigured collaborator (vault, key provider) leaves the
        # draft job intact + visible, with a stamped reason instead of a 500.
        if auto_advance:
            try:
                self.generate_keys(job)
            except OnboardingDependencyError as exc:
                self._stamp_job_error(
                    job,
                    f"تعذّر توليد مفاتيح WireGuard تلقائياً عند الإرسال: {exc}"
                )
            except OnboardingError as exc:
                self._stamp_job_error(job, str(exc))
            except Exception as exc:  # noqa: BLE001 — never crash submission on the auto-advance
                self._stamp_job_error(job, f"خطأ غير متوقّع عند توليد المفاتيح: {exc}")
        return job

    def _stamp_job_error(self, job: OnboardingJob, message: str) -> None:
        """Persist a last_error on the form_input + commit. Used when an
        auto-advance step fails but we want the draft job to remain visible
        on the dashboard so the operator can retry from the UI."""
        data = dict(job.form_input or {})
        data["last_error"] = message[:500]
        job.form_input = data
        db.session.add(job)
        db.session.commit()

    def _clear_job_error(self, job: OnboardingJob) -> None:
        """Drop a stale ``last_error`` once a step SUCCEEDS. Without this, the
        «بانتظار إعداد …» message from an earlier failed attempt (e.g. before
        the panel WG key was configured) keeps showing on the pending-
        onboardings card even after the script generates fine — a confusing
        contradiction with the «جاهز 7/7» banner. No-op when there's no error
        stamped; does NOT commit (the caller's own commit persists it)."""
        data = dict(job.form_input or {})
        if data.pop("last_error", None) is not None:
            job.form_input = data
            db.session.add(job)

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
            # Denormalize the wg-data pubkey so the proxy wg-peers publisher and
            # the panel reconcile can build peers without the job ref (feat/
            # fleet-zero-touch-sync). The private side stays vaulted; only the
            # public key lands on the row.
            wg_data_pubkey=data.public_key,
            max_sessions=form.max_sessions,
            link_speed_mbps=form.link_speed_mbps,
            weight=form.weight,
            status="provisioning",
        )
        db.session.add(node)
        db.session.flush()  # assign node.id for the FK below

        # fix/chr-unified-wg-mgmt-key-bootstrap — auto-mint REST credentials
        # when neither the per-node row nor the fleet-default carries any.
        #
        # Background: the unified script's §11 (REST API + cert + user +
        # firewall accept on wg-mgmt :8443) is gated on ``API_USER`` AND
        # ``API_PASSWORD``. A fresh node with no fleet-default password
        # produced a script that ran cleanly on the CHR but left www-ssl
        # DISABLED and no firewall accept for the metrics port — the
        # panel REST poll then returned ``connect_failed`` and
        # ``wg_verify`` reported ``rest_failed`` → the wizard stayed
        # stuck at the «سكربت» step forever, even though wg-mgmt and
        # wg-data were both healthy.
        #
        # Same bootstrap pattern as the wg keys: panel mints + panel
        # knows + panel uses. The password is stored Fernet-encrypted
        # on the node row so the live-metrics poller decrypts it on
        # read AND the script renderer pulls plaintext just-in-time
        # in :meth:`_build_bindings`.
        try:
            import secrets as _secrets
            from fleet.health.routeros_creds import (
                HARD_DEFAULT_USER, credentials_for, set_credentials,
            )
            if credentials_for(node) is None:
                set_credentials(
                    node,
                    username=HARD_DEFAULT_USER,
                    password=_secrets.token_urlsafe(24),
                )
        except Exception:  # noqa: BLE001 — never block onboarding on a creds probe
            pass

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

        BEFORE rendering, the bindings are validated against
        :mod:`fleet.registry.script_bindings_check`. If ANY critical fleet-
        infra binding is missing (panel WireGuard pubkey/endpoint, proxy
        pubkey/endpoint, shared RADIUS secret, or per-CHR keys), we refuse
        to produce a script — emitting a broken ``.rsc`` was the bug that
        burned the owner on his first real CHR install. The job stays at
        ``keys_generated`` and ``form_input.last_error`` carries the precise
        Arabic «بانتظار: …» so the dashboard surfaces exactly what to
        set up before the next attempt.
        """
        self._require(job, "script_generated")
        bindings = self._build_bindings(job)
        from fleet.registry.script_bindings_check import check_bindings, summary_ar
        missing = check_bindings(bindings)
        if missing:
            reason = summary_ar(missing)
            raise OnboardingError(reason)
        script = self.renderer.render(bindings)
        # Persist the API creds onto the node row so the live-metrics
        # poller can log in with the exact password the script just
        # provisioned. We only stage credentials when both fields are
        # present (the script render itself is what installs the user
        # on the CHR); the password is encrypted at rest via the same
        # Fernet wrapper the customer vault uses.
        api_user = str(bindings.get("API_USER") or "").strip()
        api_password = str(bindings.get("API_PASSWORD") or "")
        if api_user and api_password and job.chr_id:
            from fleet.health.routeros_creds import set_credentials
            node_row = db.session.get(FleetChrNode, job.chr_id)
            if node_row is not None:
                set_credentials(node_row, username=api_user, password=api_password)
                if bindings.get("API_PORT"):
                    node_row.routeros_api_port = int(bindings["API_PORT"])
        job.generated_script_ref = "sha256:" + hashlib.sha256(script.encode("utf-8")).hexdigest()
        # A successful render means every prerequisite is now in place —
        # clear any stale «بانتظار إعداد …» error from an earlier attempt so
        # the pending card stops contradicting the «جاهز» banner.
        self._clear_job_error(job)
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
        result = self.pusher.push(job, reach, script)
        if not result.ok:
            self.mark_failed(job, result.detail or "فشل دفع السكربت إلى العقدة.")
            raise OnboardingError(result.detail or "فشل دفع السكربت إلى العقدة.")
        # The real pusher (bootstrap_push.push_to_chr) advances+commits the job
        # itself; only advance here if it hasn't already (e.g. injected test fakes).
        if job.status != "pushed":
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
        # auto_advance=False so we drive generate_keys explicitly below (no
        # double-advance against the auto-advance in create_draft).
        job = self.create_draft(form, auto_advance=False)
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

        # wg-data address mirrors the mgmt host octet in the data pool (10.98.0.X),
        # parallel to the wg-mgmt pool (10.99.0.X) — see 06 §6.3. The script_render
        # template (StrictUndefined) requires WG_DATA_ADDR + WG_DATA_ADDR_IP.
        data_ip = f"{_WG_DATA_POOL_PREFIX}{node.wg_mgmt_ip.rsplit('.', 1)[-1]}"
        bindings: dict[str, Any] = {
            # per-CHR (the only values that differ between CHRs)
            "ROUTER_IDENTITY": node.name,
            "CHR_PUBLIC_IP": node.public_ip,
            "WG_MGMT_PRIVKEY": mgmt_priv,
            # /24 — wg-mgmt is the shared 10.99.0.0/24 control net; /32
            # left the CHR with no connected route back to the panel at
            # 10.99.0.1 (SYN-ACK fell to the default route on WAN and
            # never made it back over wg-mgmt → connect_failed on the
            # live-metrics poller). /24 gives RouterOS the connected
            # subnet route it needs. Mirrors PANEL_WG_ADDR's /24 cohort.
            "WG_MGMT_ADDR": f"{node.wg_mgmt_ip}/24",
            "WG_DATA_PRIVKEY": data_priv,
            # /24 — same reasoning on the data plane. The CHR's wg-data
            # addr (10.98.0.X) is the RADIUS src-address back to the
            # proxy at 10.98.0.1; without the connected /24 the RADIUS
            # reply path mirrored the broken wg-mgmt return path.
            "WG_DATA_ADDR": f"{data_ip}/24",
            "WG_DATA_ADDR_IP": data_ip,
        }
        # fleet-constant
        for key in _FLEET_CONST_DEFAULTS:
            bindings[key] = self._const(key)

        # Per-node role set (feat/chr-unified-provisioning-complete). The
        # template gates each VPN service + its firewall accept on this
        # SET. Empty roles_json column ⇒ all-roles-enabled (back-compat
        # for nodes registered before the column landed).
        try:
            from app.services.node_roles import enabled_roles  # local import — Flask context
            bindings["NODE_ROLES_SET"] = set(enabled_roles(node))
        except Exception:  # noqa: BLE001 — never break onboarding on a roles probe
            bindings["NODE_ROLES_SET"] = {
                "radius_transport", "vpn_sstp", "vpn_pptp",
                "vpn_ipsec", "vpn_wireguard",
            }

        # API user provisioning (live-metrics poller). Resolution: per-node
        # override on the FleetChrNode row beats Setting layer beats the
        # fleet defaults from routeros_creds. We render the PLAINTEXT
        # password into the script; the panel stores it encrypted on the
        # node row in :meth:`prepare_metrics_credentials` so the poller can
        # decrypt it later. Empty user OR password → the template's
        # ``{% if API_USER and API_PASSWORD %}`` skips the entire block.
        try:
            from fleet.health.routeros_creds import (
                decrypt_password as _dec_pwd,
                get_default_password_plaintext,
                get_default_user,
            )
            override_user = (node.routeros_api_user or "").strip()
            override_pwd = _dec_pwd(node.routeros_api_password_enc or "")
            if override_user and override_pwd:
                bindings["API_USER"] = override_user
                bindings["API_PASSWORD"] = override_pwd
            elif not bindings.get("API_USER") or not bindings.get("API_PASSWORD"):
                bindings["API_USER"] = get_default_user()
                bindings["API_PASSWORD"] = get_default_password_plaintext()
            if node.routeros_api_port:
                bindings["API_PORT"] = int(node.routeros_api_port)
        except Exception:  # noqa: BLE001 — never break onboarding on a creds probe
            pass

        # fix/chr-unified-wg-mgmt-key-bootstrap — normalise reserved usernames.
        # Live incident: the owner saved username ``admin`` on the infra
        # page; the script's ``/user remove [find name="admin"]`` is a
        # no-op (RouterOS protects the last full-group user) and the
        # following ``add`` errors with «user with such name already
        # exists». The built-in admin then keeps its ORIGINAL password —
        # not the panel's saved one — and panel REST polls fail with
        # ``auth_failed``. Compounding: on a slow CHR, ``set www-ssl
        # certificate=...`` racing the cert sign leaves www-ssl
        # disabled → connect_failed instead → wizard stuck.
        #
        # Substituting reserved names with HARD_DEFAULT_USER ("hobe-panel")
        # here means the script always provisions a clean, non-clobbering
        # row. We ALSO stamp the substitution back onto the node row so
        # ``credentials_for`` returns the SAME username the script
        # provisioned — preventing a username/password mismatch between
        # what the panel poller dials with and what the CHR knows.
        try:
            from fleet.health.routeros_creds import (
                HARD_DEFAULT_USER, set_credentials,
            )
            current_user = (bindings.get("API_USER") or "").strip().lower()
            reserved = {"admin", "root", "support", "operator"}
            if current_user in reserved:
                bindings["API_USER"] = HARD_DEFAULT_USER
                # Persist the substituted username on the row so the
                # poller uses the same name.
                if node is not None:
                    set_credentials(
                        node, username=HARD_DEFAULT_USER,
                        password=bindings["API_PASSWORD"],
                    )
                logger.warning(
                    "onboarding: API_USER=%r is a RouterOS built-in name; "
                    "substituted with HARD_DEFAULT_USER=%r for node %s",
                    current_user, HARD_DEFAULT_USER, node.name,
                )
        except Exception:  # noqa: BLE001 — never break onboarding on this guard
            pass

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
