"""Panel-side CoA-Disconnect emitter.

Signed best-effort outbound POST to the central proxy that asks it to
send RFC 5176 ``Disconnect-Request`` to every CHR currently hosting a
session for the given realm. The proxy already knows each CHR's secret
+ NAS IP — the panel just forwards the intent.

Auth model — reuses the SAME shared secret + HMAC scheme as inbound
``/api/proxy/*`` requests (see ``app/api/proxy_api._verify_proxy_token``).
The panel signs `<timestamp>:<nonce>` with HMAC-SHA256 over the shared
secret and sends it as ``X-Proxy-Token: ts:nonce:hmac``. The proxy
(when its corresponding handler ships) validates the same way.

Endpoint surface (proxy-side, build-deferred):

    POST <proxy_base>/api/proxy/coa/disconnect
    Content-Type: application/json
    X-Proxy-Token: <ts>:<nonce>:<hmac>

    { "realm": "client5",
      "reason": "panel:chr-move",
      "target_node_id": 12,
      "panel_request_id": "<uuid>" }

Response (when implemented):
    200 { "ok": true,  "sessions_kicked": <int>, "nodes": [<id>, ...] }
    501 { "ok": false, "error": "not_implemented" }     ← until the
            proxy ships the handler. We surface this as
            ``coa_status="pending_proxy_endpoint"`` to the panel UI.

Architecture notes
------------------
* **Best-effort.** The caller (chr_move) treats a failed CoA as a
  warning — the routing change is durable on its own. The customer's
  next reconnect will land on the new CHR regardless of whether CoA
  fired; CoA just shortens the disconnect window.
* **Mockable.** The whole thing is one ``emit_coa_disconnect`` function
  that tests monkeypatch. We deliberately do NOT use a requests-mock
  fixture — keeping the seam at the top of our own module means tests
  pin the panel's contract, not the HTTP plumbing.
* **No secret in logs.** The signature is constructed locally; the
  shared secret never appears in audit or log lines.
"""

from __future__ import annotations

import hashlib
import hmac
import json as _json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Optional


logger = logging.getLogger(__name__)


# CoA outcome strings the UI distinguishes. Keep stable — the customer
# detail template + the audit row both encode these verbatim.
CoaStatus = str

#: Proxy accepted the request and returned 2xx.
STATUS_OK = "ok"

#: Proxy is reachable but the CoA endpoint isn't deployed yet
#: (HTTP 404/501 etc.). This is expected before the proxy-side handler
#: ships; the panel still surfaces a useful message.
STATUS_PENDING_PROXY_ENDPOINT = "pending_proxy_endpoint"

#: Network/HTTP failure — proxy unreachable or returned 5xx. The move
#: itself is still durable; the owner can re-trigger CoA from the same
#: button.
STATUS_FAILED = "failed"

#: Panel can't sign the request — no shared secret configured. The
#: caller would have already failed inbound traffic; we surface a
#: dedicated string so the UI message is precise.
STATUS_NO_SECRET = "no_secret"

#: Panel doesn't know where the proxy lives (no PROXY_WG_ENDPOINT /
#: PROXY_HTTP_URL setting). Same intent as no_secret — distinct so the
#: operator knows which knob is missing.
STATUS_NO_ENDPOINT = "no_endpoint"


@dataclass(frozen=True)
class CoaResult:
    """What the emitter reports back to ``chr_move``.

    ``http_status`` is the real HTTP status code (or 0 if the request
    never made it onto the wire). ``message`` is short, operator-facing
    Arabic — surfaced verbatim in the result toast.
    """

    status: CoaStatus
    http_status: int = 0
    message: str = ""
    request_id: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "http_status": self.http_status,
            "message": self.message,
            "request_id": self.request_id,
            "ok": self.ok,
        }


def _resolve_proxy_secret() -> str:
    """Same chain as ``app.api.proxy_api._verify_proxy_token``: DB →
    app config. Returns ``""`` if neither has it (caller maps to
    ``STATUS_NO_SECRET``)."""
    try:
        from . import platform_settings as ps
        secret = (ps.get_secret("RADIUS_PROXY_SHARED_SECRET") or "").strip()
    except Exception:  # noqa: BLE001 — never break the panel on a settings probe
        secret = ""
    if secret:
        return secret
    try:
        from flask import current_app
        return str(current_app.config.get("RADIUS_PROXY_SHARED_SECRET") or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def _resolve_proxy_base_url() -> str:
    """Where does the proxy live? Order:
      1. ``Setting`` row ``proxy.http_base_url`` (operator-set; takes
         a full ``https://proxy.example.com:8443`` shape);
      2. ``PROXY_WG_ENDPOINT`` from the existing infra-settings module
         (host:port — wrap with ``https://``);
      3. Empty (caller maps to ``STATUS_NO_ENDPOINT``).
    """
    try:
        from app.extensions import db
        from app.models import Setting
        row = db.session.get(Setting, "proxy.http_base_url")
        if row and row.value:
            return row.value.strip().rstrip("/")
    except Exception:  # noqa: BLE001
        pass
    try:
        from fleet.registry.infra_settings import get_fleet_const
        endpoint = (get_fleet_const("PROXY_WG_ENDPOINT") or "").strip()
        if endpoint:
            # Strip any port suffix and use https on the default port.
            # The proxy presents the same wg-data endpoint hostname as
            # its REST surface in the canonical deployment.
            host = endpoint.split(":")[0]
            return f"https://{host}"
    except Exception:  # noqa: BLE001
        pass
    return ""


def _sign(secret: str, ts: int, nonce: str) -> str:
    """The same scheme inbound `/api/proxy/*` verifies — see
    ``app.api.proxy_api._verify_proxy_token``."""
    msg = f"{ts}:{nonce}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _http_post_json(url: str, payload: dict, headers: dict, *, timeout: float = 5.0):
    """Stdlib POST so the module stays dependency-free + monkey-patchable.

    Returns ``(http_status, body_text)``. Network errors raise
    ``urllib.error.URLError``; the caller wraps that as ``STATUS_FAILED``.
    """
    body = _json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.read().decode("utf-8", errors="replace") if exc.fp else "")


def emit_coa_disconnect(
    *,
    realm: str,
    target_node_id: int,
    reason: str = "panel:chr-move",
    request_id: Optional[str] = None,
    proxy_base_url: Optional[str] = None,
    shared_secret: Optional[str] = None,
) -> CoaResult:
    """Sign and POST a CoA-Disconnect intent to the proxy.

    The ``proxy_base_url`` + ``shared_secret`` args are injection seams
    for tests (production callers pass neither and resolve from the
    panel's normal config chain).

    Failure modes are mapped to stable ``CoaStatus`` strings the UI
    surfaces verbatim — see module docstring.
    """
    rid = request_id or uuid.uuid4().hex
    secret = (shared_secret or _resolve_proxy_secret()).strip()
    if not secret:
        logger.warning(
            "coa_disconnect: no RADIUS_PROXY_SHARED_SECRET configured — "
            "cannot sign the CoA emission for realm=%s", realm,
        )
        return CoaResult(
            status=STATUS_NO_SECRET,
            message=(
                "لم يُعدّ السر المشترك (RADIUS_PROXY_SHARED_SECRET) "
                "بعد — اضبطه من «إعدادات المنصّة» ثم أعد المحاولة."
            ),
            request_id=rid,
        )
    base = (proxy_base_url if proxy_base_url is not None else _resolve_proxy_base_url()).rstrip("/")
    if not base:
        logger.warning(
            "coa_disconnect: no proxy base URL configured (proxy.http_base_url "
            "or PROXY_WG_ENDPOINT) — cannot route CoA emission for realm=%s",
            realm,
        )
        return CoaResult(
            status=STATUS_NO_ENDPOINT,
            message=(
                "لم تُعدّ نقطة وصول الوكيل بعد — اضبطها من «إعدادات بنية "
                "الأسطول» ثم أعد المحاولة."
            ),
            request_id=rid,
        )

    ts = int(time.time())
    nonce = uuid.uuid4().hex
    header_token = f"{ts}:{nonce}:{_sign(secret, ts, nonce)}"

    url = f"{base}/api/proxy/coa/disconnect"
    payload = {
        "realm": realm,
        "reason": reason,
        "target_node_id": int(target_node_id),
        "panel_request_id": rid,
    }
    try:
        http_status, _ = _http_post_json(
            url, payload,
            headers={"X-Proxy-Token": header_token},
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning(
            "coa_disconnect: emit failed realm=%s err=%s", realm, exc,
        )
        return CoaResult(
            status=STATUS_FAILED, http_status=0,
            message=(
                "تعذّر الوصول إلى الوكيل لإرسال CoA — التحويل تمّ على "
                "خرائط التوجيه، اضغط «إعادة فصل» لاحقًا حين يعود الوكيل."
            ),
            request_id=rid,
        )

    if 200 <= http_status < 300:
        return CoaResult(
            status=STATUS_OK, http_status=http_status,
            message="تمّ إرسال CoA-Disconnect إلى الوكيل بنجاح.",
            request_id=rid,
        )
    if http_status in (404, 405, 501):
        # The proxy doesn't (yet) implement the endpoint. The owner's
        # routing change has still landed; surface a clear «بانتظار»
        # state instead of a misleading «فشل».
        return CoaResult(
            status=STATUS_PENDING_PROXY_ENDPOINT, http_status=http_status,
            message=(
                "تمّ تحديث التوجيه، لكن نقطة CoA على الوكيل غير مُفعَّلة "
                "بعد — ستفعّل تلقائيًا حين يُحدَّث الوكيل."
            ),
            request_id=rid,
        )
    return CoaResult(
        status=STATUS_FAILED, http_status=http_status,
        message=(
            f"رفض الوكيل طلب CoA (HTTP {http_status}). التوجيه محدَّث؛ "
            "أعد المحاولة من نفس الزر."
        ),
        request_id=rid,
    )


__all__ = [
    "CoaResult",
    "STATUS_OK",
    "STATUS_PENDING_PROXY_ENDPOINT",
    "STATUS_FAILED",
    "STATUS_NO_SECRET",
    "STATUS_NO_ENDPOINT",
    "emit_coa_disconnect",
]
