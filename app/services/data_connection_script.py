"""Version-aware client-script generator for VPS-direct DATA connections.

feat/data-connection-panel (Phase 2b). Emits the customer-MikroTik
``.rsc`` for an SSTP or PPTP CLIENT that dials the customer's RADIUS VPS
**directly** (``clientN.hoberadius.com``) — served by accel-ppp + a real
Let's Encrypt cert. There is **no CHR and no proxy** anywhere in the
generated script: the connection terminates on the VPS.

Why version-aware: RouterOS v6 and v7 differ for SSTP/PPTP clients
(connect-to/port syntax, default-route handling). The generator branches
on ``ros_version`` so the operator gets a paste-ready script for the
subscriber's exact RouterOS.

Pure + side-effect-free: inputs in → ``.rsc`` string out. ASCII-only.
Secrets (password) are passed in and rendered verbatim; the caller
decides redaction for display.
"""
from __future__ import annotations

import re

PROTOCOLS = ("sstp", "pptp")
ROS_VERSIONS = ("6", "7")

#: Default SSTP TLS port on the VPS (accel-ppp [sstp] port=443).
DEFAULT_SSTP_PORT = 443

#: Fixed DATA speed (informational, in the comment) — 5 Mbit, enforced
#: server-side by the accel-ppp Filter-Id (2a), NOT in the client script.
DATA_SPEED_LABEL = "5M"

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class DataConnectionScriptError(ValueError):
    """Invalid input for the client-script generator (Arabic message)."""


def _clean_name(name: str) -> str:
    """RouterOS interface/comment-safe name (the «name as comment» that
    must be set via the MikroTik config, not a RADIUS attr)."""
    n = _SAFE_NAME.sub("-", (name or "").strip()).strip("-.")
    return (n or "hobe-data")[:63]


def _validate(*, server: str, username: str, password: str,
              protocol: str, ros_version: str) -> None:
    if not server or " " in server or '"' in server:
        raise DataConnectionScriptError("عنوان الخادم (subdomain) غير صالح.")
    if not username or '"' in username:
        raise DataConnectionScriptError("اسم المستخدم غير صالح.")
    if not password or '"' in password:
        raise DataConnectionScriptError("كلمة المرور غير صالحة.")
    if protocol not in PROTOCOLS:
        raise DataConnectionScriptError("البروتوكول يجب أن يكون sstp أو pptp.")
    if str(ros_version) not in ROS_VERSIONS:
        raise DataConnectionScriptError("إصدار RouterOS يجب أن يكون 6 أو 7.")


def _header(server: str, protocol: str, ros_version: str, name: str) -> str:
    return (
        f"# HobeRadius DATA connection ({protocol.upper()} client, RouterOS v{ros_version})\n"
        f"# Target: {server}  (direct to RADIUS VPS via accel-ppp + Let's Encrypt cert)\n"
        f"# Speed: {DATA_SPEED_LABEL} (enforced server-side); unlimited data.\n"
        f"# Connection name/comment: {name}\n"
    )


# ════════════════════════════════════════════════════════════════════════
# SSTP
# ════════════════════════════════════════════════════════════════════════
def _sstp_v6(server, port, user, pw, name, add_default_route) -> str:
    # v6: connect-to takes host; port is a SEPARATE field. The real LE cert
    # on `server` lets verify-server-certificate=yes work with NO CA import.
    adr = "yes" if add_default_route else "no"
    return (
        "/interface sstp-client\n"
        f'add name="{name}" connect-to={server} port={port} \\\n'
        f'    user="{user}" password="{pw}" \\\n'
        "    profile=default-encryption \\\n"
        "    verify-server-certificate=yes \\\n"
        f"    add-default-route={adr} \\\n"
        f'    disabled=no comment="{name}"\n'
    )


def _sstp_v7(server, port, user, pw, name, add_default_route) -> str:
    # v7: connect-to is host-only (port via the separate `port=`); v7 adds
    # tls-version; default-route is expressed via add-default-route on the
    # interface (kept for parity — route distance tuning is left to the op).
    adr = "yes" if add_default_route else "no"
    return (
        "/interface sstp-client\n"
        f'add name="{name}" connect-to={server} port={port} \\\n'
        f'    user="{user}" password="{pw}" \\\n'
        "    profile=default-encryption \\\n"
        "    verify-server-certificate=yes tls-version=only-1.2 \\\n"
        f"    add-default-route={adr} \\\n"
        f'    disabled=no comment="{name}"\n'
    )


# ════════════════════════════════════════════════════════════════════════
# PPTP
# ════════════════════════════════════════════════════════════════════════
def _pptp_v6(server, user, pw, name, add_default_route) -> str:
    adr = "yes" if add_default_route else "no"
    return (
        "/interface pptp-client\n"
        f'add name="{name}" connect-to={server} \\\n'
        f'    user="{user}" password="{pw}" \\\n'
        "    profile=default-encryption \\\n"
        f"    add-default-route={adr} \\\n"
        f'    disabled=no comment="{name}"\n'
    )


def _pptp_v7(server, user, pw, name, add_default_route) -> str:
    # v7: same menu; profile=default-encryption must be set explicitly
    # (v7 changed the implicit encryption default).
    adr = "yes" if add_default_route else "no"
    return (
        "/interface pptp-client\n"
        f'add name="{name}" connect-to={server} \\\n'
        f'    user="{user}" password="{pw}" \\\n'
        "    profile=default-encryption \\\n"
        f"    add-default-route={adr} \\\n"
        f'    disabled=no comment="{name}"\n'
    )


def render_client_rsc(
    *,
    server: str,
    username: str,
    password: str,
    protocol: str,
    ros_version: str,
    name: str = "hobe-data",
    sstp_port: int = DEFAULT_SSTP_PORT,
    add_default_route: bool = False,
) -> str:
    """Render the customer-MikroTik ``.rsc`` for a DATA connection.

    ``server`` is the VPS subdomain (clientN.hoberadius.com) — NEVER a CHR
    or panel IP. Raises :class:`DataConnectionScriptError` on bad input.
    """
    protocol = (protocol or "").strip().lower()
    ros_version = str(ros_version or "").strip()
    _validate(server=server, username=username, password=password,
              protocol=protocol, ros_version=ros_version)
    nm = _clean_name(name)
    body: str
    if protocol == "sstp":
        port = int(sstp_port or DEFAULT_SSTP_PORT)
        body = (_sstp_v6 if ros_version == "6" else _sstp_v7)(
            server, port, username, password, nm, add_default_route)
    else:  # pptp
        body = (_pptp_v6 if ros_version == "6" else _pptp_v7)(
            server, username, password, nm, add_default_route)
    return _header(server, protocol, ros_version, nm) + "\n" + body


__all__ = [
    "PROTOCOLS", "ROS_VERSIONS", "DEFAULT_SSTP_PORT",
    "DataConnectionScriptError", "render_client_rsc",
]
