"""fleet.sync.wg_apply — apply desired wg-mgmt peers on the PANEL HOST.

The app runs unprivileged (systemd ``User=hoberadius``) and has no business
holding root. So peer application is delegated to ONE tiny, scoped root helper
installed once by ``deploy/zero_touch/install_wg_helper.sh``:

    /usr/local/sbin/hobe-wg-sync   (root-owned, mode 0755)

A scoped sudoers line lets ``hoberadius`` run ONLY that command with no
password. The app hands the helper the desired peer set as JSON on stdin; the
helper rewrites just the ``[Peer]`` blocks of ``/etc/wireguard/wg-mgmt.conf``
(never the ``[Interface]`` private key) and runs ``wg syncconf``, then prints
the applied peer pubkeys back as JSON. That is the entire privileged surface.

SAFE BY DEFAULT — this module performs a privileged action only when the helper
binary actually exists on disk (i.e. the operator ran the one-time installer).
On dev/Windows/CI, or on a production host before setup, every function here is
a pure no-op that REPORTS "helper not installed" and changes nothing. It never
raises and never shells out blindly.
"""
from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — used only for the single scoped wg helper
from dataclasses import dataclass, field

#: Default install path for the scoped helper. Overridable via Flask config
#: ``ZERO_TOUCH_WG_HELPER`` (e.g. for a non-FHS layout or a test fixture).
_DEFAULT_HELPER = "/usr/local/sbin/hobe-wg-sync"
_MGMT_INTERFACE = "wg-mgmt"
_HELPER_TIMEOUT = 15.0


@dataclass(frozen=True)
class ApplyResult:
    """Outcome of a panel-host peer apply (or the no-op when unavailable)."""

    available: bool          # is the root helper installed?
    applied: bool            # did we successfully sync peers?
    applied_pubkeys: list[str] = field(default_factory=list)
    desired_count: int = 0
    message: str = ""        # Arabic, operator-facing

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "applied": self.applied,
            "applied_pubkeys": list(self.applied_pubkeys),
            "desired_count": self.desired_count,
            "message": self.message,
        }


def _helper_path() -> str:
    try:
        from flask import current_app
        configured = str(current_app.config.get("ZERO_TOUCH_WG_HELPER") or "").strip()
        if configured:
            return configured
    except Exception:  # noqa: BLE001 — no app context (tests) → default
        pass
    return _DEFAULT_HELPER


def helper_installed() -> bool:
    """True iff the scoped root helper exists on this host."""
    path = _helper_path()
    return bool(path) and os.path.isfile(path)


def _run_helper(action: str, payload: dict | None) -> tuple[bool, str]:
    """Invoke ``sudo -n <helper> <action>`` with optional JSON stdin.

    Returns ``(ok, stdout_or_error)``. Never raises.
    """
    helper = _helper_path()
    argv = ["sudo", "-n", helper, action]
    try:
        proc = subprocess.run(  # nosec B603 — fixed argv, scoped helper only
            argv,
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            timeout=_HELPER_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return False, "sudo/helper غير موجود على هذا المضيف."
    except subprocess.TimeoutExpired:
        return False, "انتهت مهلة تنفيذ أداة المزامنة على مضيف اللوحة."
    except Exception as exc:  # noqa: BLE001 — privileged call must never crash caller
        return False, f"تعذّر تشغيل أداة المزامنة: {exc.__class__.__name__}"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return False, err or f"رمز خروج غير صفري ({proc.returncode})."
    return True, (proc.stdout or "").strip()


def apply_panel_peers(peers) -> ApplyResult:
    """Apply the desired wg-mgmt peer set on the panel host.

    ``peers`` is a list of :class:`fleet.sync.peers.WgPeer`. When the helper is
    absent this is a reported no-op (``available=False``) — the wg-mgmt
    handshake stage will still surface the real on-host truth.
    """
    desired = [
        {"public_key": p.public_key, "allowed_ips": list(p.allowed_ips), "name": p.name}
        for p in peers
        if (p.public_key or "").strip()
    ]
    if not helper_installed():
        return ApplyResult(
            available=False, applied=False, desired_count=len(desired),
            message=(
                "أداة مزامنة WireGuard على مضيف اللوحة غير مثبَّتة بعد — "
                "نُفِّذ التثبيت لمرة واحدة عبر deploy/zero_touch/install_wg_helper.sh. "
                "حتى ذلك الحين تُنشَر المفاتيح ويُتحقَّق من المصافحة فعلياً دون تطبيق محلي."
            ),
        )

    ok, out = _run_helper("apply", {"interface": _MGMT_INTERFACE, "peers": desired})
    if not ok:
        return ApplyResult(
            available=True, applied=False, desired_count=len(desired),
            message=f"تعذّر تطبيق نظراء wg-mgmt على مضيف اللوحة: {out}",
        )
    applied_pubkeys: list[str] = []
    try:
        parsed = json.loads(out) if out else {}
        applied_pubkeys = [str(k) for k in (parsed.get("applied_pubkeys") or [])]
    except (ValueError, TypeError):
        applied_pubkeys = []
    return ApplyResult(
        available=True, applied=True, applied_pubkeys=applied_pubkeys,
        desired_count=len(desired),
        message=f"تمت مزامنة {len(applied_pubkeys)} نظيراً على واجهة wg-mgmt للوحة.",
    )


def current_panel_peer_pubkeys() -> list[str] | None:
    """The wg-mgmt peer pubkeys currently trusted on the panel host.

    Returns ``None`` when the helper is unavailable (we genuinely don't know),
    or a (possibly empty) list when it is. Never raises.
    """
    if not helper_installed():
        return None
    ok, out = _run_helper("show", None)
    if not ok:
        return None
    try:
        parsed = json.loads(out) if out else {}
        return [str(k) for k in (parsed.get("peers") or [])]
    except (ValueError, TypeError):
        return None


__all__ = [
    "ApplyResult",
    "apply_panel_peers",
    "current_panel_peer_pubkeys",
    "helper_installed",
]
