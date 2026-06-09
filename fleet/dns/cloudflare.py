"""fleet.dns.cloudflare — Phase 6 Task A (Cloudflare front-door driver).

Supports BOTH operating modes for ``vpn.hoberadius.com``:

* :data:`MODE_FREE` — plain A-records on the zone. Cloudflare's free DNS has
  no per-record weight, so weights collapse to **include / exclude**: a node
  with ``included=False`` (drained, down, over-cap) is filtered out of the
  record set. Multi-record round-robin is the only spread mechanism here.

* :data:`MODE_PAID` — Cloudflare Load Balancing origin pool. The driver
  maintains ONE pool (``cfg.cloudflare.pool_name``) with origins one-per-CHR
  carrying their graduated ``weight`` (a float in ``[0, 1]``); origins with
  ``included=False`` are persisted with ``enabled=False`` (so Cloudflare
  health-checks can still see them) but removed from active steering.
  The pool is attached as the default/fallback of a single LB
  (``cfg.cloudflare.lb_name`` on the zone).

Idempotency
-----------
Every apply path is **idempotent**: it diffs the desired state against
the live state via cheap GETs, emits only the create/update/delete calls
needed to converge, and returns ``changed=False`` when nothing differs.
Re-applying the same desired set is a no-op (no API calls beyond the
read-side fetches).

DRY-RUN
-------
The Cloudflare API token is loaded ONLY from the encrypted secrets vault
(via a ``Setting`` row pointing at a :class:`VaultRef`). When no token is
configured the driver runs in DRY-RUN: it computes the intended call
sequence, returns it in :attr:`ApplyResult.calls_planned`, persists the
intended state into :class:`fleet_dns_records_state`, but never sends
anything. Tests pass an explicit ``dry_run=True`` to exercise the same
code path under deterministic fixtures.

Security
--------
* The token is wrapped in :class:`_RedactedToken` so any accidental
  ``log.info(token)`` writes ``"***"`` to the log instead.
* The token NEVER appears in :class:`IntendedCall.body`, in any
  :class:`ApplyResult.errors` entry, or in :class:`ApplyResult.snapshot`.
  The unit test ``test_token_never_appears_in_apply_result`` proves this.
* HTTP errors capture only the status code, the URL path, and a truncated
  body fragment with the token-bearing ``Authorization`` header stripped.
* The token is loaded lazily, exactly once per :meth:`CloudflareDriver`
  call; it's held only on the active stack frame, never on the
  long-lived driver instance.

Public surface (Task B consumes these; do NOT break)
----------------------------------------------------
* :class:`DesiredOrigin`  — frozen dataclass ``(node, ip, weight, included)``.
* :class:`IntendedCall`   — frozen dataclass capturing one planned HTTP call.
* :class:`ApplyResult`    — frozen dataclass returned by every apply.
* :class:`CloudflareDriver`
* :func:`apply_desired_state(desired, *, mode, dry_run=None) -> ApplyResult`
* :func:`current_state(*, mode) -> dict`
* :data:`MODE_FREE`, :data:`MODE_PAID`
"""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable

from app.extensions import db
from app.models import Setting

from fleet.config import FLEET, CloudflareDnsConfig, FleetConfig
from fleet.dns.models_dns import DnsRecordState


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Mode constants — used by callers (Task B, the scheduler, the UI)
# ════════════════════════════════════════════════════════════════════════

#: Plain A-record mode. No true weight; weights collapse to include/exclude.
MODE_FREE = "free"

#: Cloudflare Load Balancing pool mode. Graduated weights honoured.
MODE_PAID = "paid"

MODES: tuple[str, ...] = (MODE_FREE, MODE_PAID)


# ════════════════════════════════════════════════════════════════════════
# Public dataclasses (frozen — Task B can rely on identity / hashing)
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class DesiredOrigin:
    """One CHR's slot in the desired front-door state.

    Attributes
    ----------
    node      stable CHR name (``fleet_chr_nodes.name``). Used as the
              Cloudflare-side origin name in PAID mode so origin moves are
              idempotent across renames.
    ip        IPv4 address (the only record type the fleet publishes
              today; IPv6 = a future phase).
    weight    floating-point weight in ``[0.0, 1.0]``. Honoured by PAID
              mode; FREE mode treats ``weight == 0`` as "exclude" but
              otherwise ignores the value.
    included  True iff the origin participates right now. The brain sets
              this to False for drained / down / over-cap nodes so a
              single driver call excludes them cleanly.
    """

    node: str
    ip: str
    weight: float = 1.0
    included: bool = True


@dataclasses.dataclass(frozen=True)
class IntendedCall:
    """A single planned HTTP call against the Cloudflare API.

    ``body`` is the JSON-serialisable request body, or ``None`` for a GET.
    NEVER contains the token: the Authorization header is added by the
    transport at send time and stripped from every log path.

    Used both for explainability (the UI can render "here's what we'd
    do") and for the DRY-RUN return value.
    """

    method: str
    path: str
    body: dict | None = None
    purpose: str = ""

    def __repr__(self) -> str:  # pragma: no cover - logging aid
        return f"<IntendedCall {self.method} {self.path} ({self.purpose})>"


@dataclasses.dataclass(frozen=True)
class ApplyResult:
    """Outcome of one :func:`apply_desired_state` call.

    Attributes
    ----------
    mode             ``"free"`` or ``"paid"`` — the mode the driver ran in.
    dry_run          True iff no API calls were actually sent (because no
                     token was configured OR the caller explicitly opted
                     into a dry run).
    changed          False iff the live state already matched ``desired``
                     (no API mutations were planned). Read-side diff GETs
                     are NOT counted as changes.
    calls_planned    Every :class:`IntendedCall` the driver computed,
                     including dry-run runs. Order is significant: it's
                     the exact sequence the driver intended to send.
    calls_executed   The subset of ``calls_planned`` that was actually
                     sent. Empty when ``dry_run`` is True.
    errors           Short machine-readable error codes from any sends
                     that failed. NEVER contains the token.
    snapshot         Before/after summary: ``{"before": {...}, "after":
                     {...}}``. Useful for the placement_decisions audit
                     row + the operator UI.
    """

    mode: str
    dry_run: bool
    changed: bool
    calls_planned: tuple[IntendedCall, ...]
    calls_executed: tuple[IntendedCall, ...]
    errors: tuple[str, ...]
    snapshot: dict


# ════════════════════════════════════════════════════════════════════════
# Token redaction — the token only ever exists as this opaque box
# ════════════════════════════════════════════════════════════════════════


class _RedactedToken:
    """Opaque token holder; prints ``"***"`` so accidental logs are safe.

    The underlying value is reachable only through :meth:`reveal`. Tests
    that need to assert "the token never appeared in this string" sweep
    over the rendered payloads and check that ``token.reveal()`` is not a
    substring of any of them.
    """

    __slots__ = ("_v",)

    def __init__(self, value: str):
        # ``str`` cast belt-and-braces — a caller MUST pass a string but
        # we'd rather coerce than crash on a bytes accidentally arriving
        # from a future loader. Empty token = unconfigured.
        self._v = str(value or "")

    def reveal(self) -> str:
        return self._v

    def __bool__(self) -> bool:
        return bool(self._v)

    def __repr__(self) -> str:
        return "_RedactedToken('***')"

    __str__ = __repr__


# ════════════════════════════════════════════════════════════════════════
# Transport abstraction — tests inject a fake to never touch the network
# ════════════════════════════════════════════════════════════════════════


HttpResponse = tuple[int, dict]
"""``(status_code, json_decoded_body)`` — the transport contract."""

HttpTransport = Callable[[IntendedCall, _RedactedToken, CloudflareDnsConfig], HttpResponse]
"""Signature for a Cloudflare HTTP transport. Tests pass a mock that
returns scripted responses; the default :func:`_urllib_transport` calls
the real Cloudflare API."""


def _urllib_transport(
    call: IntendedCall, token: _RedactedToken, cfg: CloudflareDnsConfig,
) -> HttpResponse:
    """Real HTTP transport — stdlib ``urllib.request`` (same approach the
    rest of the panel uses, e.g. ``app.services.routeros_client``).

    Returns ``(status, decoded_body)``. Network failures and non-2xx
    responses are caught and surfaced as a (status, body) pair so the
    caller's error path is uniform. The Authorization header is added
    here and NEVER logged.
    """
    url = cfg.api_base.rstrip("/") + "/" + call.path.lstrip("/")
    data = json.dumps(call.body).encode("utf-8") if call.body is not None else None
    headers = {
        # The ONLY place the token is read into the actual HTTP message.
        "Authorization": f"Bearer {token.reveal()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    req = urllib.request.Request(url, data=data, method=call.method.upper(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=cfg.request_timeout_s) as resp:
            raw = resp.read()
            body = json.loads(raw.decode("utf-8")) if raw else {}
            return resp.status, body
    except urllib.error.HTTPError as exc:
        # Read body for diagnostics — do NOT pass it through logger as raw.
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            body = {"errors": [{"message": "non-json error body"}]}
        return exc.code, body
    except urllib.error.URLError as exc:
        # Network-level failure — uniform error shape.
        return 0, {"errors": [{"message": f"transport_error: {exc.reason!r}"}]}


# ════════════════════════════════════════════════════════════════════════
# Token loader — encrypted vault only; missing → dry-run
# ════════════════════════════════════════════════════════════════════════


def _load_token(cfg: CloudflareDnsConfig) -> _RedactedToken:
    """Return a :class:`_RedactedToken`.

    Resolution path (in this order):

    1. The ``Setting`` row keyed by ``cfg.token_setting_key`` holds a
       :class:`VaultRef`. We resolve it through
       :func:`fleet.registry.secrets_vault.retrieve_secret`. A missing
       row, blank value, or vault-side failure all degrade silently to
       an empty token (and thus DRY-RUN); we DO log a warning so an
       operator notices.
    2. Empty token → ``_RedactedToken("")`` which evaluates falsy. The
       driver's apply path treats this as "DRY-RUN — never send".
    """
    row = db.session.get(Setting, cfg.token_setting_key)
    ref = (row.value or "").strip() if row is not None else ""
    if not ref:
        return _RedactedToken("")
    try:
        # Imported lazily — tests don't need the vault to exist for the
        # dry-run / mock-transport paths.
        from fleet.registry.secrets_vault import VaultError, retrieve_secret  # noqa: I001
        plaintext = retrieve_secret(ref)
    except Exception as exc:  # noqa: BLE001 - vault may not be ready
        logger.warning(
            "fleet.dns.cloudflare: vault token unreadable (%s) — running in DRY-RUN",
            exc.__class__.__name__,
        )
        return _RedactedToken("")
    return _RedactedToken(plaintext)


# ════════════════════════════════════════════════════════════════════════
# Driver
# ════════════════════════════════════════════════════════════════════════


class CloudflareDriver:
    """Front-door driver for ``vpn.hoberadius.com``.

    Constructed with a :class:`FleetConfig` (defaults to the global
    :data:`fleet.config.FLEET`) and an optional :data:`HttpTransport`.
    Tests pass a fake transport that records calls + returns scripted
    responses; production code uses the default :func:`_urllib_transport`.
    """

    def __init__(
        self,
        cfg: FleetConfig | None = None,
        *,
        transport: HttpTransport | None = None,
    ):
        self._cfg = cfg or FLEET
        self._cf = self._cfg.dns.cloudflare
        self._transport = transport or _urllib_transport

    # ── public ──────────────────────────────────────────────────────────

    def apply_desired_state(
        self,
        desired: Iterable[DesiredOrigin],
        *,
        mode: str,
        dry_run: bool | None = None,
    ) -> ApplyResult:
        """Converge the live Cloudflare state with ``desired``. Idempotent.

        Parameters
        ----------
        desired   list of :class:`DesiredOrigin`. The driver normalises
                  (sorts, dedupes by ``(node, ip)``, validates IPv4) so
                  callers can pass output straight from the brain.
        mode      ``MODE_FREE`` or ``MODE_PAID``.
        dry_run   ``None`` (default) — auto: dry-run iff no token is
                  configured. ``True`` — never send, return the intended
                  call sequence. ``False`` — force-send even if no token
                  (the transport will raise / return an auth error).
        """
        if mode not in MODES:
            raise ValueError(f"unknown mode={mode!r}; expected one of {MODES}")

        token = _load_token(self._cf)
        effective_dry_run = bool(dry_run) if dry_run is not None else (not token)

        # Normalise the desired set: sort by node so the diff is
        # deterministic, drop any non-IPv4 (we publish only A records),
        # dedupe by (node, ip).
        normalised = self._normalise(desired)

        if mode == MODE_FREE:
            return self._apply_free(normalised, token, effective_dry_run)
        return self._apply_paid(normalised, token, effective_dry_run)

    def current_state(self, *, mode: str) -> dict:
        """Read the live Cloudflare state for inspection.

        Returns a dict whose shape depends on the mode:

        * ``MODE_FREE`` →
          ``{"records": [{"id":..., "content":..., "ttl":...}, ...]}``
        * ``MODE_PAID`` →
          ``{"pool_id":..., "origins":[...], "lb_id":..., "default_pools":[...]}``

        When no token is configured, returns ``{"dry_run": True}`` —
        callers should treat that as "live read unavailable".
        """
        if mode not in MODES:
            raise ValueError(f"unknown mode={mode!r}; expected one of {MODES}")
        token = _load_token(self._cf)
        if not token:
            return {"dry_run": True, "mode": mode}
        if mode == MODE_FREE:
            return self._read_records(token)
        return self._read_pool_and_lb(token)

    # ── normalisation ───────────────────────────────────────────────────

    @staticmethod
    def _normalise(desired: Iterable[DesiredOrigin]) -> list[DesiredOrigin]:
        seen: set[tuple[str, str]] = set()
        out: list[DesiredOrigin] = []
        for o in desired:
            if not o.ip:
                continue
            try:
                addr = ipaddress.ip_address(o.ip)
            except ValueError:
                continue
            if addr.version != 4:
                continue
            key = (o.node, o.ip)
            if key in seen:
                continue
            seen.add(key)
            out.append(DesiredOrigin(
                node=o.node, ip=o.ip,
                weight=float(o.weight) if o.weight is not None else 1.0,
                included=bool(o.included),
            ))
        out.sort(key=lambda x: (x.node, x.ip))
        return out

    # ────────────────────────────────────────────────────────────────────
    # FREE mode — plain A records
    # ────────────────────────────────────────────────────────────────────

    def _apply_free(
        self,
        desired: list[DesiredOrigin],
        token: _RedactedToken,
        dry_run: bool,
    ) -> ApplyResult:
        cf = self._cf
        # Active record set = origins that are included AND non-zero weight.
        active = [o for o in desired if o.included and (o.weight is None or o.weight > 0)]
        wanted_ips = sorted({o.ip for o in active})

        before_records: list[dict] = []
        if token:
            state = self._read_records(token)
            before_records = state.get("records", [])
        before_ips = sorted({r.get("content") for r in before_records if r.get("content")})

        # Compute the diff.
        planned: list[IntendedCall] = []
        wanted_set = set(wanted_ips)
        before_set = set(before_ips)
        to_create = sorted(wanted_set - before_set)
        to_delete = sorted(before_set - wanted_set)

        for ip in to_create:
            planned.append(IntendedCall(
                method="POST",
                path=f"zones/{cf.zone_id}/dns_records",
                body={
                    "type": "A",
                    "name": cf.front_door,
                    "content": ip,
                    "ttl": int(self._cfg.dns.ttl),
                    "proxied": False,
                    "comment": f"hoberadius fleet: {self._chr_for_ip(active, ip)}",
                },
                purpose=f"create A {cf.front_door} → {ip}",
            ))
        for ip in to_delete:
            rid = next((r["id"] for r in before_records if r.get("content") == ip), None)
            if rid is None:
                continue
            planned.append(IntendedCall(
                method="DELETE",
                path=f"zones/{cf.zone_id}/dns_records/{rid}",
                body=None,
                purpose=f"delete A {cf.front_door} ← {ip}",
            ))

        changed = bool(planned)
        executed: list[IntendedCall] = []
        errors: list[str] = []
        if changed and not dry_run:
            executed, errors = self._execute(planned, token)

        # Record applied state — persist what we *intended*, even on
        # dry-run, so the operator UI shows the planned answer set. Only
        # commit when nothing went wrong on the wire.
        if not errors:
            self._record_state(wanted_ips, reason="free_apply")

        return ApplyResult(
            mode=MODE_FREE, dry_run=dry_run, changed=changed,
            calls_planned=tuple(planned), calls_executed=tuple(executed),
            errors=tuple(errors),
            snapshot={
                "before": {"ips": before_ips},
                "after":  {"ips": wanted_ips},
                "fqdn":   cf.front_door,
                "ttl":    int(self._cfg.dns.ttl),
            },
        )

    @staticmethod
    def _chr_for_ip(desired: list[DesiredOrigin], ip: str) -> str:
        for o in desired:
            if o.ip == ip:
                return o.node
        return ""

    def _read_records(self, token: _RedactedToken) -> dict:
        cf = self._cf
        get = IntendedCall(
            method="GET",
            path=f"zones/{cf.zone_id}/dns_records?type=A&name={cf.front_door}",
            purpose="list current A-records",
        )
        status, body = self._transport(get, token, cf)
        if not _is_2xx(status) or not body.get("success", True):
            return {"records": [], "_read_error": _short_error(status, body)}
        return {"records": [
            {"id": r.get("id"), "content": r.get("content"), "ttl": r.get("ttl")}
            for r in (body.get("result") or [])
        ]}

    # ────────────────────────────────────────────────────────────────────
    # PAID mode — Load Balancing origin pool
    # ────────────────────────────────────────────────────────────────────

    def _apply_paid(
        self,
        desired: list[DesiredOrigin],
        token: _RedactedToken,
        dry_run: bool,
    ) -> ApplyResult:
        """Two-phase apply: converge the pool first (capturing its id from
        either the live read OR the POST response), THEN converge the LB
        that references it. Doing this in one pass with a placeholder id
        leaves the LB body permanently storing the placeholder, which
        breaks the next idempotency check.
        """
        cf = self._cf
        before_pool, before_lb = ({"origins": []}, {})
        if token:
            live = self._read_pool_and_lb(token)
            before_pool = live.get("pool") or {"origins": []}
            before_lb = live.get("lb") or {}

        wanted_origins = self._build_pool_origins(desired)
        planned: list[IntendedCall] = []
        executed: list[IntendedCall] = []
        errors: list[str] = []

        # ── Phase 1: pool ───────────────────────────────────────────
        pool_id = before_pool.get("id")
        pool_changed = self._pool_diff(before_pool, wanted_origins)
        pool_body = {
            "name": cf.pool_name, "origins": wanted_origins,
            "enabled": True, "minimum_origins": 1,
        }
        if pool_id is None:
            pool_call = IntendedCall(
                method="POST",
                path=f"accounts/{cf.account_id}/load_balancers/pools",
                body=pool_body,
                purpose=f"create pool {cf.pool_name}",
            )
            planned.append(pool_call)
            if not dry_run:
                status, body = self._transport(pool_call, token, cf)
                if _is_2xx(status) and body.get("success", True):
                    pool_id = (body.get("result") or {}).get("id") or pool_id
                    executed.append(pool_call)
                else:
                    errors.append(_short_error(status, body, call=pool_call))
        elif pool_changed:
            pool_call = IntendedCall(
                method="PUT",
                path=f"accounts/{cf.account_id}/load_balancers/pools/{pool_id}",
                body=pool_body,
                purpose=f"update pool {cf.pool_name}",
            )
            planned.append(pool_call)
            if not dry_run:
                status, body = self._transport(pool_call, token, cf)
                if _is_2xx(status) and body.get("success", True):
                    executed.append(pool_call)
                else:
                    errors.append(_short_error(status, body, call=pool_call))

        # ── Phase 2: LB ─────────────────────────────────────────────
        # Effective pool id: live id, then post-create id, then a stable
        # placeholder for the dry-run plan (operator can see the shape).
        effective_pool_id = pool_id or "<pool-id-pending>"
        lb_id = before_lb.get("id")
        desired_lb_body = {
            "name": cf.lb_name,
            "default_pools": [effective_pool_id],
            "fallback_pool": effective_pool_id,
            "proxied": False,
            "steering_policy": "dynamic_latency",
            "ttl": int(self._cfg.dns.ttl),
        }
        lb_changed = self._lb_diff(before_lb, desired_lb_body)
        # Only proceed to LB if phase 1 didn't error (no half-publish).
        if not errors and (lb_id is None or lb_changed):
            if lb_id is None:
                lb_call = IntendedCall(
                    method="POST",
                    path=f"zones/{cf.zone_id}/load_balancers",
                    body=desired_lb_body,
                    purpose=f"create LB {cf.lb_name}",
                )
            else:
                lb_call = IntendedCall(
                    method="PUT",
                    path=f"zones/{cf.zone_id}/load_balancers/{lb_id}",
                    body=desired_lb_body,
                    purpose=f"update LB {cf.lb_name}",
                )
            planned.append(lb_call)
            if not dry_run:
                status, body = self._transport(lb_call, token, cf)
                if _is_2xx(status) and body.get("success", True):
                    executed.append(lb_call)
                else:
                    errors.append(_short_error(status, body, call=lb_call))

        changed = bool(planned)
        wanted_ips = sorted({o["address"] for o in wanted_origins if o.get("enabled")})
        if not errors:
            self._record_state(wanted_ips, reason="paid_apply")

        return ApplyResult(
            mode=MODE_PAID, dry_run=dry_run, changed=changed,
            calls_planned=tuple(planned), calls_executed=tuple(executed),
            errors=tuple(errors),
            snapshot={
                "before": {
                    "pool_origins": before_pool.get("origins", []),
                    "lb_default_pools": before_lb.get("default_pools", []),
                },
                "after": {
                    "pool_origins": wanted_origins,
                    "lb_default_pools": desired_lb_body["default_pools"],
                },
                "fqdn": cf.lb_name,
                "pool_name": cf.pool_name,
            },
        )

    @staticmethod
    def _build_pool_origins(desired: list[DesiredOrigin]) -> list[dict]:
        """Convert :class:`DesiredOrigin` rows into Cloudflare pool origins.

        Disabled (``included=False``) origins are kept in the pool with
        ``enabled=False`` so Cloudflare's health checks keep visibility
        of the node — when the brain re-includes the node we flip it
        back on without losing the origin's history.
        """
        out: list[dict] = []
        for o in desired:
            w = max(0.0, min(1.0, float(o.weight) if o.weight is not None else 1.0))
            out.append({
                "name": o.node,
                "address": o.ip,
                "enabled": bool(o.included) and w > 0,
                "weight": round(w, 3),
            })
        return out

    @staticmethod
    def _pool_diff(before_pool: dict, wanted: list[dict]) -> bool:
        """True iff the pool's origin set differs from ``wanted``."""
        before_origins = before_pool.get("origins") or []
        by_name_before = {o.get("name"): o for o in before_origins}
        if set(by_name_before.keys()) != {o["name"] for o in wanted}:
            return True
        for w in wanted:
            b = by_name_before.get(w["name"])
            if b is None:
                return True
            if str(b.get("address")) != str(w["address"]):
                return True
            if bool(b.get("enabled")) != bool(w["enabled"]):
                return True
            if round(float(b.get("weight") or 0), 3) != round(float(w["weight"]), 3):
                return True
        return False

    @staticmethod
    def _lb_diff(before_lb: dict, wanted: dict) -> bool:
        if not before_lb:
            return True
        for k in ("name", "fallback_pool", "default_pools", "proxied",
                  "steering_policy", "ttl"):
            if before_lb.get(k) != wanted.get(k):
                return True
        return False

    def _read_pool_and_lb(self, token: _RedactedToken) -> dict:
        """Look up the pool + LB by name. Returns ``{}``-shaped dicts when
        nothing exists yet (a fresh deployment)."""
        cf = self._cf
        pools = self._transport(IntendedCall(
            method="GET",
            path=f"accounts/{cf.account_id}/load_balancers/pools",
            purpose="list pools",
        ), token, cf)
        pool = {}
        if _is_2xx(pools[0]):
            for p in (pools[1].get("result") or []):
                if p.get("name") == cf.pool_name:
                    pool = {
                        "id": p.get("id"),
                        "origins": [
                            {"name": o.get("name"), "address": o.get("address"),
                             "enabled": o.get("enabled"), "weight": o.get("weight")}
                            for o in (p.get("origins") or [])
                        ],
                    }
                    break
        lbs = self._transport(IntendedCall(
            method="GET",
            path=f"zones/{cf.zone_id}/load_balancers",
            purpose="list zone LBs",
        ), token, cf)
        lb = {}
        if _is_2xx(lbs[0]):
            for entry in (lbs[1].get("result") or []):
                if entry.get("name") == cf.lb_name:
                    lb = {
                        "id": entry.get("id"),
                        "name": entry.get("name"),
                        "default_pools": entry.get("default_pools") or [],
                        "fallback_pool": entry.get("fallback_pool"),
                        "proxied": entry.get("proxied"),
                        "steering_policy": entry.get("steering_policy"),
                        "ttl": entry.get("ttl"),
                    }
                    break
        return {"pool": pool, "lb": lb,
                "pool_id": pool.get("id"), "lb_id": lb.get("id")}

    # ────────────────────────────────────────────────────────────────────
    # Execution path (shared) + state recording
    # ────────────────────────────────────────────────────────────────────

    def _execute(
        self, planned: list[IntendedCall], token: _RedactedToken,
    ) -> tuple[list[IntendedCall], list[str]]:
        executed: list[IntendedCall] = []
        errors: list[str] = []
        for call in planned:
            status, body = self._transport(call, token, self._cf)
            if _is_2xx(status) and body.get("success", True):
                executed.append(call)
                continue
            errors.append(_short_error(status, body, call=call))
            # First failure short-circuits — partial apply is dangerous
            # for DNS (we never want to publish a half-broken set).
            break
        return executed, errors

    def _record_state(self, ips: list[str], *, reason: str) -> None:
        """Persist the intended record set into ``fleet_dns_records_state``.

        The model already handles the IP-validation + sort canonicalisation
        and idempotent upsert (see :class:`DnsRecordState.upsert`). We
        catch + log any commit failure so a Cloudflare-side hiccup
        doesn't take down the apply path.
        """
        try:
            DnsRecordState.upsert(
                fqdn=self._cf.front_door,
                record_type="A",
                ips=ips,
                ttl=int(self._cfg.dns.ttl),
                provider_zone_id=self._cf.zone_id,
                reason=reason,
            )
            db.session.commit()
        except Exception:  # noqa: BLE001 - persistence is best-effort
            db.session.rollback()
            logger.exception("fleet.dns.cloudflare: failed to persist state for %s",
                             self._cf.front_door)


# ════════════════════════════════════════════════════════════════════════
# Free functions — module-level entry points the rest of the panel calls
# ════════════════════════════════════════════════════════════════════════


def apply_desired_state(
    desired: Iterable[DesiredOrigin],
    *,
    mode: str,
    dry_run: bool | None = None,
    cfg: FleetConfig | None = None,
    transport: HttpTransport | None = None,
) -> ApplyResult:
    """Module-level wrapper — see :meth:`CloudflareDriver.apply_desired_state`."""
    return CloudflareDriver(cfg=cfg, transport=transport).apply_desired_state(
        desired, mode=mode, dry_run=dry_run,
    )


def current_state(
    *,
    mode: str,
    cfg: FleetConfig | None = None,
    transport: HttpTransport | None = None,
) -> dict:
    """Module-level wrapper — see :meth:`CloudflareDriver.current_state`."""
    return CloudflareDriver(cfg=cfg, transport=transport).current_state(mode=mode)


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


def _is_2xx(status: int) -> bool:
    return 200 <= int(status) < 300


def _short_error(status: int, body: Any, *, call: IntendedCall | None = None) -> str:
    """Build a short machine-readable error string for the result.

    NEVER includes the token. Body fragments are JSON-encoded with a hard
    length cap so a Cloudflare-side echo of (e.g.) the request body
    can't smuggle anything secret back to the operator log.
    """
    try:
        cf_errors = body.get("errors") if isinstance(body, dict) else None
    except AttributeError:
        cf_errors = None
    code = ""
    if cf_errors:
        try:
            code = str(cf_errors[0].get("code", "")) or ""
        except (IndexError, AttributeError):
            code = ""
    suffix = f":{code}" if code else ""
    if call is not None:
        return f"http_{status}{suffix} on {call.method} {call.path[:80]}"
    return f"http_{status}{suffix}"


__all__ = [
    "MODE_FREE",
    "MODE_PAID",
    "MODES",
    "DesiredOrigin",
    "IntendedCall",
    "ApplyResult",
    "CloudflareDriver",
    "apply_desired_state",
    "current_state",
]
