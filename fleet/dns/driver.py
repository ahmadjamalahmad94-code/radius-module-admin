"""fleet.dns.driver — provider-neutral driver entry point (Phase-6 gate shim).

The reconcile adapter (``fleet.dns.driver_adapter``) discovers the real driver by
importing ``fleet.dns.driver`` first. Task A shipped the Cloudflare driver as
``fleet.dns.cloudflare``; this module re-exports its public surface under the
name the adapter looks for, so ``DRIVER_BACKEND`` flips from "fake" to "real"
without either side having to know the other's module name.
"""
from fleet.dns.cloudflare import (
    ApplyResult,
    CloudflareDriver,
    DesiredOrigin,
    MODE_FREE,
    MODE_PAID,
    apply_desired_state,
    current_state,
)

__all__ = [
    "apply_desired_state",
    "current_state",
    "CloudflareDriver",
    "DesiredOrigin",
    "ApplyResult",
    "MODE_FREE",
    "MODE_PAID",
]
