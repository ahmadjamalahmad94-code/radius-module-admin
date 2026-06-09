"""fleet.dns.driver_adapter — single import surface for the DNS driver.

The reconciler (``fleet.dns.reconcile``) does not call provider APIs
directly; it always goes through this adapter. That gives us two things:

* The Cloudflare/PowerDNS/Route53 driver work (Phase-6 task A) can ship
  independently — the reconciler is already coded against the frozen
  contract below.
* Tests get a deterministic, in-process fake that records every call so
  the reconciler's behaviour is verifiable without network or env vars.

Frozen contract (matches the task brief)::

    apply_desired_state(desired, *, mode, dry_run) -> ApplyResult

    desired = list of NodeRecord(node, ip, weight, included)
    mode    = one of {"WEIGHTED_ROUND_ROBIN", "ROUND_ROBIN", "FAILOVER"}
    dry_run = bool — when True, driver computes the diff but does not
              touch the provider API (the reconciler ALSO short-circuits
              earlier when nothing changed; ``dry_run=True`` is a stronger
              "regardless, do not call out" guarantee for the operator
              preview / no-token environments).

    ApplyResult carries:
        applied        bool — whether the provider was actually mutated
        changed        bool — whether the desired set differs from the
                              previous state (driver-observed)
        published_ips  list[str] — sorted IPs the driver intends to publish
        message        str — short human-readable status
        mode           str — echo of the mode used
        dry_run        bool — echo
        raw            dict — driver-specific debugging payload (optional)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence


# ─────────────────────────────────────────────────────────────────────────────
# Frozen wire-facing types
# ─────────────────────────────────────────────────────────────────────────────
#: Modes the reconciler may request. Phase-6 gate: canonicalised to the
#: driver's vocabulary ("free" = weighted A-records / exclusion; "paid" =
#: Cloudflare load-balancer). The reconciler always computes weights so the
#: same desired-state works in either mode.
DRIVER_MODES: tuple[str, ...] = ("free", "paid")


@dataclass(frozen=True)
class NodeRecord:
    """One entry in the desired DNS record set.

    ``included`` is the structural flag — when False the node is excluded
    from publication even if it appears in the list (used for traceability:
    the reconciler may emit excluded entries so the audit row carries the
    full ``why this one didn't make it``).
    """

    node: str
    ip: str
    weight: int
    included: bool = True


@dataclass(frozen=True)
class ApplyResult:
    """What the driver did (or would have done)."""

    applied: bool
    changed: bool
    published_ips: list[str]
    message: str = ""
    mode: str = ""
    dry_run: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Backend resolution
# ─────────────────────────────────────────────────────────────────────────────
#: Marker set by ``_resolve_driver()``. Useful for the UI / smoke tests to
#: tell whether the real Cloudflare driver is wired up ("real") or the
#: in-process fake is in play ("fake").
DRIVER_BACKEND: str = "unresolved"


def _resolve_driver() -> Callable[..., ApplyResult] | None:
    """Return the real driver's ``apply_desired_state`` or ``None``.

    Lazy + idempotent so a test that monkey-patches ``fleet.dns.driver``
    mid-run is honoured. Tried locations, in order:

    1. ``fleet.dns.driver.apply_desired_state``                    (any provider)
    2. ``fleet.dns.providers.cloudflare.apply_desired_state``      (P6-T1)
    3. ``fleet.dns.providers.base.apply_desired_state``            (P6-T1 base)
    """
    global DRIVER_BACKEND
    for module_path in (
        "fleet.dns.driver",
        "fleet.dns.providers.cloudflare",
        "fleet.dns.providers.base",
    ):
        try:
            mod = __import__(module_path, fromlist=("apply_desired_state",))
        except ImportError:
            continue
        real = getattr(mod, "apply_desired_state", None)
        if callable(real):
            DRIVER_BACKEND = "real"
            return real
    DRIVER_BACKEND = "fake"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# In-process fake — only used until the real driver lands
# ─────────────────────────────────────────────────────────────────────────────
#: Append-only log of every ``apply_desired_state`` call the fake handled.
#: Tests pop entries off this list to assert what the reconciler asked for.
#: Reset between tests with ``reset_fake_calls()``.
FAKE_CALLS: list[dict[str, Any]] = []


def reset_fake_calls() -> None:
    FAKE_CALLS.clear()


def _fake_apply(
    desired: Sequence[NodeRecord],
    *,
    mode: str,
    dry_run: bool,
) -> ApplyResult:
    """Compute the publish set + return an ``ApplyResult``; never network.

    The fake's ``applied`` flag mirrors ``not dry_run``: in real life the
    reconciler short-circuits before calling the driver when nothing
    changed, so by the time we reach the driver we either apply (dry_run
    False) or we don't (dry_run True). Tests use ``FAKE_CALLS`` to verify
    the request shape.
    """
    publishable = [r for r in desired if r.included]
    published_ips = sorted({r.ip for r in publishable})
    FAKE_CALLS.append({
        "desired": [
            {"node": r.node, "ip": r.ip, "weight": r.weight, "included": r.included}
            for r in desired
        ],
        "mode": mode,
        "dry_run": dry_run,
        "published_ips": published_ips,
    })
    return ApplyResult(
        applied=(not dry_run) and bool(published_ips),
        changed=bool(published_ips),
        published_ips=published_ips,
        message=("would publish (dry run)" if dry_run else "published (fake driver)"),
        mode=mode,
        dry_run=dry_run,
        raw={"backend": "fake", "publishable_count": len(publishable)},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API — what the reconciler imports
# ─────────────────────────────────────────────────────────────────────────────
def apply_desired_state(
    desired: Sequence[NodeRecord],
    *,
    mode: str,
    dry_run: bool,
) -> ApplyResult:
    """Apply (or preview) the desired DNS state.

    ``desired`` is a list of ``NodeRecord`` produced by the reconciler.
    Only entries with ``included=True`` are publishable; the others ride
    along for audit purposes. ``mode`` must be one of :data:`DRIVER_MODES`
    (the driver may ignore weights for the simpler modes). ``dry_run=True``
    instructs the driver NOT to touch the provider regardless of diff.

    The adapter:

    * Validates ``mode``.
    * Tries the real driver first; if absent uses the in-process fake.
    * Returns ``ApplyResult`` — never raises on backend selection; a real
      driver is free to raise on provider errors and the reconciler maps
      those to its own audit row.
    """
    if mode not in DRIVER_MODES:
        raise ValueError(
            f"mode must be one of {DRIVER_MODES}, got {mode!r}"
        )
    real = _resolve_driver()
    if real is not None:
        return _coerce_apply_result(
            real(desired, mode=mode, dry_run=dry_run),
            desired, mode=mode, dry_run=dry_run,
        )
    return _fake_apply(desired, mode=mode, dry_run=dry_run)


def _coerce_apply_result(
    res: Any,
    desired: Sequence[NodeRecord],
    *,
    mode: str,
    dry_run: bool,
) -> ApplyResult:
    """Normalise whatever the real driver returned into this adapter's
    ``ApplyResult`` (the shape the reconciler reads: ``applied`` / ``message`` /
    ``published_ips`` …).

    Phase-6 gate: task A's Cloudflare driver returns its OWN ApplyResult
    (``mode``/``dry_run``/``changed``/``calls_planned``/``calls_executed``/
    ``errors``/``snapshot``) which lacks ``applied``/``message``/``published_ips``.
    Map it here so the reconciler binds to either backend.
    """
    if isinstance(res, ApplyResult):
        return res
    # A driver already exposing the adapter contract (a test double / future
    # provider) → trust its fields.
    if hasattr(res, "applied") and hasattr(res, "published_ips"):
        return ApplyResult(
            applied=bool(res.applied),
            changed=bool(getattr(res, "changed", False)),
            published_ips=list(getattr(res, "published_ips", []) or []),
            message=str(getattr(res, "message", "") or ""),
            mode=str(getattr(res, "mode", mode) or mode),
            dry_run=bool(getattr(res, "dry_run", dry_run)),
            raw=dict(getattr(res, "raw", {}) or {}),
        )
    # Cloudflare (task A) ApplyResult shape.
    executed = list(getattr(res, "calls_executed", ()) or ())
    planned = list(getattr(res, "calls_planned", ()) or ())
    errors = list(getattr(res, "errors", ()) or ())
    res_dry = bool(getattr(res, "dry_run", dry_run))
    changed = bool(getattr(res, "changed", False))
    applied = (not res_dry) and bool(executed) and not errors
    published_ips = sorted({r.ip for r in desired if getattr(r, "included", True)})
    if errors:
        message = "; ".join(str(e) for e in errors)[:300]
    elif res_dry:
        message = f"dry-run ({len(planned)} call(s) planned)"
    else:
        message = f"applied {len(executed)} call(s)"
    return ApplyResult(
        applied=applied,
        changed=changed,
        published_ips=published_ips,
        message=message,
        mode=str(getattr(res, "mode", mode) or mode),
        dry_run=res_dry,
        raw=dict(getattr(res, "snapshot", {}) or {}),
    )


__all__ = [
    "ApplyResult",
    "NodeRecord",
    "DRIVER_MODES",
    "DRIVER_BACKEND",
    "FAKE_CALLS",
    "apply_desired_state",
    "reset_fake_calls",
]
