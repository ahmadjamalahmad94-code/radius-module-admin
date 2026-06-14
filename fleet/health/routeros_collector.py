"""fleet.health.routeros_collector — read live RouterOS metrics over wg-mgmt.

A small wrapper on top of :class:`app.services.routeros_client.RouterOSClient`
that returns ONE poll's worth of data per node in a single dataclass. The
metrics poller turns that into a ``fleet_chr_metrics`` row with
``source='control'``.

What it reads (and why):

* **CPU** — ``/rest/system/resource.cpu_load`` (0–100 int). Drives the
  scoring brain's shed threshold (``HealthConfig.cpu_shed_threshold_pct``)
  + the dashboard's «المعالج» chip.
* **Memory** — ``/rest/system/resource`` total/free → percentage. Surfaced
  for dashboard parity with CPU.
* **Active sessions** — ``len(/rest/ppp/active) + len(/rest/ip/ipsec/active-peers)``.
  PPP covers SSTP/PPTP/L2TP; IPsec covers IKEv2. Sum is what the brain's
  capacity factor consumes.
* **RX / TX bytes** — cumulative interface counters from
  ``/rest/interface/{WAN}`` (defaults to ``ether1``). The brain diffs
  these across samples to compute bandwidth + bytes-this-cycle; we just
  record the raw counter values per sample.

The collector NEVER raises. A connection failure, auth failure, or a
single missing field returns a :class:`Sample` with the affected fields
set to ``None`` plus a short ``error`` code so the poller can log it
without taking the worker down. Plaintext passwords are passed straight
into the underlying :class:`RouterOSClient` and never echoed back.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Any

from app.services.routeros_client import RouterOSClient, RouterOSError

from fleet.health.routeros_creds import credentials_for
from fleet.registry.models_chr import FleetChrNode


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Sample shape
# ════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class Sample:
    """One poll's worth of data per node. All fields nullable."""

    cpu_pct: float | None = None
    mem_pct: float | None = None
    active_sessions: int | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    uptime: str = ""
    error: str = ""
    error_detail: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


# ════════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════════


def collect(node: FleetChrNode, *, wan_iface: str = "ether1",
            client_factory=None, timeout: int = 8) -> Sample:
    """Poll a single node and return a :class:`Sample`.

    ``client_factory`` is the unit-test seam. Production code passes
    ``None`` and the function builds a real :class:`RouterOSClient`
    using the panel-stored credentials. Tests pass a callable
    ``(host, port, user, password) → SomeFakeClient`` so the real HTTP
    layer is never reached.
    """
    creds = credentials_for(node)
    if creds is None:
        return Sample(error="no_credentials")

    client = (client_factory or _default_client_factory)(
        host=creds["host"], port=creds["port"],
        user=creds["user"], password=creds["password"],
        timeout=timeout,
    )

    try:
        resource = client.system_resource() or {}
    except RouterOSError as exc:
        # fix/chr-rollback-wgdata-rest (issue 3 part 4) -- make the
        # transport UNAMBIGUOUS in the panel log. The panel speaks ONLY
        # REST over https://<host>:<port>/rest/ (there is no binary-API
        # client anywhere in the codebase). On an auth failure we log
        # the REST URL + user explicitly so a CHR-side «login failure
        # for user X via api» line can be matched to a panel-side REST
        # poll (RouterOS labels REST auth failures "via api"). This
        # proves the panel is NOT probing legacy api/api-ssl.
        if (exc.code or "") == "auth_failed":
            logger.warning(
                "routeros_collector: REST AUTH FAILED node=%s user=%s "
                "transport=REST url=https://%s:%s/rest/ -- the CHR's "
                "hobe-panel password must equal the panel-stored secret "
                "(NOT a legacy-api probe; panel has no binary-api client)",
                node.name, creds["user"], creds["host"], creds["port"],
            )
        return Sample(error=exc.code or "routeros_error",
                      error_detail=str(getattr(exc, "message", ""))[:160])
    except Exception as exc:  # noqa: BLE001 — never crash the poller
        logger.exception("routeros_collector: unexpected error on %s", node.name)
        return Sample(error="unexpected", error_detail=exc.__class__.__name__)

    cpu_pct = _coerce_pct(resource.get("cpu-load"))
    mem_pct = _mem_pct_from_resource(resource)
    uptime = str(resource.get("uptime") or "")

    # Active sessions: PPP + IPsec. Either count failing returns None for
    # the field rather than killing the whole sample.
    active = _active_session_count(client)

    # WAN interface counters. We pull the row for the configured WAN
    # interface so the brain can compute bandwidth/used-tb from successive
    # samples. A missing row returns (None, None).
    rx, tx = _wan_bytes(client, wan_iface)

    return Sample(
        cpu_pct=cpu_pct, mem_pct=mem_pct,
        active_sessions=active,
        rx_bytes=rx, tx_bytes=tx,
        uptime=uptime,
    )


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════


def _default_client_factory(
    *, host: str, port: int, user: str, password: str, timeout: int,
) -> RouterOSClient:
    """Real production transport. The collector handles every error path,
    so we let the client raise its native :class:`RouterOSError`."""
    return RouterOSClient(
        host=host, port=port,
        username=user, password=password,
        use_tls=True, verify_tls=False,
        timeout=timeout,
    )


def _coerce_pct(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(100.0, f))


def _mem_pct_from_resource(resource: dict) -> float | None:
    """RouterOS reports total + free memory in bytes (as strings). We
    compute used / total × 100 here so the poller writes the same scale
    the dashboard expects (0–100 float)."""
    total = _coerce_int(resource.get("total-memory") or resource.get("total_memory"))
    free = _coerce_int(resource.get("free-memory") or resource.get("free_memory"))
    if total is None or free is None or total <= 0:
        return None
    used = max(0, total - free)
    return round(100.0 * used / total, 2)


def _coerce_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _active_session_count(client) -> int | None:
    """Best-effort count: PPP active + IPsec active peers. A single failure
    on either path contributes 0 rather than blanking the field."""
    ppp_n = 0
    ipsec_n = 0
    seen_any = False
    try:
        ppp_n = len(client.list_ppp_active() or [])
        seen_any = True
    except RouterOSError:
        pass
    except Exception:  # noqa: BLE001 — never crash
        pass
    try:
        ipsec_n = len(client.list_ipsec_active_peers() or [])
        seen_any = True
    except RouterOSError:
        pass
    except Exception:  # noqa: BLE001
        pass
    if not seen_any:
        return None
    return ppp_n + ipsec_n


def _wan_bytes(client, wan_iface: str) -> tuple[int | None, int | None]:
    """Read RX/TX cumulative counters off the WAN interface."""
    try:
        rows = client.list_interfaces() or []
    except RouterOSError:
        return None, None
    except Exception:  # noqa: BLE001
        return None, None
    for row in rows:
        if str(row.get("name") or "") == wan_iface:
            return _coerce_int(row.get("rx-byte") or row.get("rx_byte")), \
                   _coerce_int(row.get("tx-byte") or row.get("tx_byte"))
    return None, None


__all__ = ["Sample", "collect"]
