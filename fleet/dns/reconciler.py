"""fleet.dns.reconciler — settings-aware front-door reconciler (Phase-6 gate).

Task C's UI view imports ``from fleet.dns import reconciler`` and calls
``reconciler.preview()`` / ``reconciler.reconcile_now()`` with no args. The real
engine lives in ``fleet.dns.reconcile`` and takes a :class:`ReconcileConfig`.

This module is the bridge: it reads the operator's saved front-door settings
(task C's :mod:`fleet.dns.settings_store`) — the **mode** (``free``/``paid``) and
whether a **token** is configured — builds a ``ReconcileConfig`` from them, and
delegates to the real reconciler. Wiring the chain end to end:

    UI settings (mode + token)  →  reconciler  →  reconcile  →  driver_adapter  →  cloudflare driver

``dry_run`` is forced True when no token is configured: the adapter always passes
an explicit bool to the driver (so the driver's own auto-dry-run never triggers),
therefore the reconciler must decide dry-run from token presence to honour the
"no token ⇒ never call Cloudflare" contract.
"""
from __future__ import annotations

from typing import Any

from fleet.dns import reconcile as _reconcile
from fleet.dns import settings_store
from fleet.dns.reconcile import ReconcileConfig

# Re-export the compute-side helpers other callers may want.
compute_desired = _reconcile.compute_desired
normalize_weights = _reconcile.normalize_weights
ReconcileResult = _reconcile.ReconcileResult
DesiredState = _reconcile.DesiredState


def _config_from_settings(*, dry_run_override: bool | None = None) -> ReconcileConfig:
    """Build a ReconcileConfig from the saved front-door settings.

    mode    ← settings_store front-door mode ("free" | "paid")
    dry_run ← True when no token is configured (unless explicitly overridden)
    """
    view = settings_store.load_view()
    mode = view["mode"]  # already validated to free|paid by the store
    if dry_run_override is not None:
        dry_run = dry_run_override
    else:
        dry_run = not settings_store.token_is_set()
    return ReconcileConfig(mode=mode, dry_run=dry_run)


def preview(cfg: ReconcileConfig | None = None) -> ReconcileResult:
    """Compute the intended DNS state without applying. Never calls Cloudflare."""
    return _reconcile.preview(cfg=cfg or _config_from_settings(dry_run_override=True))


def reconcile_now(cfg: ReconcileConfig | None = None) -> ReconcileResult:
    """Apply the intended DNS state. Dry-run (no provider call) when no token."""
    return _reconcile.reconcile_now(cfg=cfg or _config_from_settings())


__all__ = [
    "preview",
    "reconcile_now",
    "compute_desired",
    "normalize_weights",
    "ReconcileConfig",
    "ReconcileResult",
    "DesiredState",
]
