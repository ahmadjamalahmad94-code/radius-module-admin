"""Per-customer accel-ppp install bundle (DATA connection, 2c).

Serves the activation bundle (``setup-radius-vps.sh`` + its sibling template and
agent files) as a single ``.tar.gz`` so the owner can install on an EXISTING VPS
with ONE ``curl … | tar`` — no GitHub token, no scp. The customer's
``SUBDOMAIN``/``VPS_IP`` and ``CERT_CHALLENGE=dns01`` are pre-filled as the
script defaults (the owner still passes the SECRETS — RADIUS_SECRET, the
Cloudflare token, certbot email — at runtime, so NO secret is ever baked into
the downloadable bundle).

The HTTP endpoint is token-gated (itsdangerous-signed, tied to the customer id)
so the VPS can fetch it unauthenticated while random enumeration is blocked. The
bundle itself contains only non-secret install scaffolding.
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path

from flask import current_app
from itsdangerous import BadSignature, URLSafeSerializer

from app.models import Customer

from .customer_subdomain import customer_fqdn

#: Repo deploy dir holding the canonical sources (same files cloud-init embeds).
_DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "accel-ppp"

#: Files included in the bundle, with (arcname, source path, mode).
_BUNDLE_FILES = (
    ("accel-ppp/setup-radius-vps.sh", _DEPLOY / "setup-radius-vps.sh", 0o755),
    ("accel-ppp/accel-ppp.conf.tmpl", _DEPLOY / "accel-ppp.conf.tmpl", 0o644),
    ("accel-ppp/agent/vps_agent.py", _DEPLOY / "agent" / "vps_agent.py", 0o755),
    ("accel-ppp/agent/__init__.py", _DEPLOY / "agent" / "__init__.py", 0o644),
)

_TOKEN_SALT = "data-connection-bundle-v1"


def _serializer() -> URLSafeSerializer:
    return URLSafeSerializer(current_app.config["SECRET_KEY"], salt=_TOKEN_SALT)


def bundle_token(customer_id: int) -> str:
    """A stable, signed token tying a download URL to one customer id."""
    return _serializer().dumps(int(customer_id))


def verify_bundle_token(token: str) -> int | None:
    """Return the customer id a token authorizes, or ``None`` if invalid."""
    try:
        return int(_serializer().loads(token or ""))
    except (BadSignature, ValueError, TypeError):
        return None


def _prefilled_script(customer: Customer) -> bytes:
    """The activation script with this customer's non-secret defaults baked in:
    SUBDOMAIN (deterministic FQDN), VPS_IP (if set), and CERT_CHALLENGE=dns01
    (the owner's box has the panel on :80, so HTTP-01 would clash)."""
    text = (_DEPLOY / "setup-radius-vps.sh").read_text(encoding="utf-8")
    fqdn = customer_fqdn(customer)
    ip = (customer.vps_ip or "").strip()
    # Literal substitutions on the `${VAR:-default}` tokens (unique substrings).
    text = text.replace('SUBDOMAIN="${SUBDOMAIN:-}"', f'SUBDOMAIN="${{SUBDOMAIN:-{fqdn}}}"')
    if ip:
        text = text.replace('VPS_IP="${VPS_IP:-}"', f'VPS_IP="${{VPS_IP:-{ip}}}"')
    text = text.replace('CERT_CHALLENGE="${CERT_CHALLENGE:-auto}"',
                        'CERT_CHALLENGE="${CERT_CHALLENGE:-dns01}"')
    return text.encode("utf-8")


def build_bundle_targz(customer: Customer) -> bytes:
    """Build the in-memory ``.tar.gz`` bundle for ``customer``.

    Deterministic (fixed mtime/uid/gid) so the same customer yields the same
    bytes. The setup script is pre-filled; every other file is verbatim.
    """
    prefilled = _prefilled_script(customer)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        for arcname, src, mode in _BUNDLE_FILES:
            data = prefilled if arcname.endswith("setup-radius-vps.sh") else src.read_bytes()
            info = tarfile.TarInfo(name=arcname)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


__all__ = [
    "bundle_token", "verify_bundle_token", "build_bundle_targz",
]
