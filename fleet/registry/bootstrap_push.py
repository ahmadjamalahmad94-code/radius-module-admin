"""fleet.registry.bootstrap_push — Phase 3 task T4 (one-time bootstrap channel).

When a new CHR is being onboarded the panel needs to push the rendered
RouterOS provisioning script (see ``script_render.py``, P3-T3) into the
RouterOS device ONE TIME, before the ``wg-mgmt`` control tunnel exists. That
first push runs over a one-shot channel using whatever reachability the
owner supplied in the wizard (``initial_host``, ``initial_port``,
``initial_username``, ``initial_password``).

Once the script has been applied, the CHR has ``wg-mgmt`` up and the panel
SWITCHES to that tunnel for every future command — the bootstrap channel
must be closed/firewalled afterwards (the docstring of :class:`PushResult`
restates this invariant for the caller).

Design constraints (per docs/chr_fleet/06_ONBOARDING_WIZARD.md §6.6 and
07_CONTROL_PLANE.md §7.5):

* The bootstrap password / API token MUST NOT be persisted in plaintext —
  it lives ONLY in the wizard's form data + the in-process :class:`Pusher`
  context, OR (when the operator opts in) in the secrets vault under a
  short-lived ref. This module never logs the password.
* The pusher is a single transport boundary. The actual RouterOS transport
  (REST over HTTPS, SSH, legacy API) is pluggable via :class:`Transport` so
  P3-T3 / future phases can swap implementations and the integration tests
  can pass a fake transport without touching real network code.
* Pushes are idempotent: every onboarding script is written so re-running it
  yields the same end state (§6.8). The pusher records the post-push
  outcome on ``OnboardingJob`` (advances ``status``: ``script_generated →
  pushed`` on success, ``... → failed`` on error) so the wizard's state
  machine stays honest.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Callable, Protocol

from app.extensions import db
from app.models import utcnow

from fleet.registry.models_onboarding import OnboardingJob

logger = logging.getLogger(__name__)


# ───────────────────────── transport abstraction ─────────────────────────

class Transport(Protocol):
    """A pluggable one-shot RouterOS transport.

    Implementations only need to satisfy :meth:`push_script`. The pusher
    wraps every call in a ``try/finally`` that calls :meth:`close` exactly
    once, even on exception, so the bootstrap channel is firewall-safe by
    construction.
    """

    def push_script(self, script: str) -> "TransportResult":  # noqa: D401 - protocol
        """Send ``script`` to the CHR and return what RouterOS replied."""

    def close(self) -> None:
        """Release any underlying resources (TCP socket, REST session, …).

        Called by :class:`Pusher` exactly once in a ``finally`` block, even
        when :meth:`push_script` raised. Implementations MUST be idempotent.
        """


@dataclasses.dataclass(frozen=True)
class TransportResult:
    """Raw outcome from the transport's POV — pre-orchestration verdict.

    ``ok`` is True when the device acknowledged the script. ``output`` is the
    transport's stdout/REST body for the audit log. ``error`` is a short
    machine-readable cause when ``ok`` is False (``"auth_failed"``,
    ``"network_unreachable"``, ``"script_error"``, …).
    """

    ok: bool
    output: str = ""
    error: str = ""
    latency_ms: int = 0


# ───────────────────────── bootstrap target ─────────────────────────

@dataclasses.dataclass(frozen=True)
class BootstrapTarget:
    """The one-time reach-out parameters the owner supplied in the wizard.

    Per ``06_ONBOARDING_WIZARD.md`` §6.1 the wizard collects:
    *initial RouterOS reach (host:port + creds, one-time)* — used once,
    not stored plaintext. We treat ``password`` as untracked secret material:
    the dataclass is frozen, the ``__repr__`` redacts it, and the field is
    cleared from the in-process :class:`Pusher` as soon as the transport
    completes.
    """

    host: str
    port: int = 8729             # RouterOS api-ssl default; SSH = 22
    username: str = "admin"
    password: str = ""
    transport_kind: str = "api"  # 'api' | 'ssh' (informational, used by factory)

    def __repr__(self) -> str:
        return (
            f"BootstrapTarget(host={self.host!r}, port={self.port}, "
            f"username={self.username!r}, transport_kind={self.transport_kind!r}, "
            f"password='<redacted>')"
        )

    __str__ = __repr__


# ───────────────────────── push result for the caller ─────────────────────────

@dataclasses.dataclass(frozen=True)
class PushResult:
    """High-level outcome of a bootstrap push.

    A successful push means: the device accepted and applied the script. The
    caller (onboarding service P3-T1) then runs ``verifying`` checks — see
    §6.7 — before promoting the CHR to ``active``.

    INVARIANT — after this returns, the bootstrap channel has been closed
    by the pusher; future communication MUST go through ``wg-mgmt``. The
    caller does NOT need to call ``close()`` on anything.
    """

    ok: bool
    job_id: int
    new_status: str          # whatever status the job advanced TO
    error: str = ""          # short machine-readable cause when ok is False
    raw_output: str = ""     # transport's stdout/REST body, for the audit log
    latency_ms: int = 0


# ───────────────────────── transport factory ─────────────────────────

#: Public registry of transport factories keyed by ``transport_kind``.
#: Production wiring (REST over HTTPS, ssh+RouterOS API) will add entries
#: here in Phase 7 (P7-T3). Tests register a fake via :func:`register_transport`.
_TRANSPORT_FACTORIES: dict[str, Callable[[BootstrapTarget], Transport]] = {}


def register_transport(kind: str, factory: Callable[[BootstrapTarget], Transport]) -> None:
    """Register or replace the factory for ``transport_kind``.

    Calling with ``factory=None`` removes the registration. Idempotent —
    test fixtures and Phase-7 wiring can both call it without ordering
    concerns.
    """
    if factory is None:
        _TRANSPORT_FACTORIES.pop(kind, None)
        return
    _TRANSPORT_FACTORIES[kind] = factory


def _resolve_transport(target: BootstrapTarget) -> Transport:
    factory = _TRANSPORT_FACTORIES.get(target.transport_kind)
    if factory is None:
        raise BootstrapError(
            f"no transport registered for kind={target.transport_kind!r}. "
            "Phase-7 wiring or a test fixture must register one via "
            "register_transport()."
        )
    return factory(target)


# ───────────────────────── exceptions ─────────────────────────

class BootstrapError(RuntimeError):
    """Raised for bootstrap-pusher orchestration failures.

    NEVER carries the bootstrap password in its message — callers may log it.
    """


# ───────────────────────── the pusher ─────────────────────────

class Pusher:
    """Single-use one-time pusher tied to one onboarding job.

    Usage::

        pusher = Pusher(job)
        result = pusher.push(target, script)
        # bootstrap channel closed automatically; future commands go over wg-mgmt

    Or as a context manager (preferred — close() is guaranteed even on
    early exception)::

        with Pusher(job) as pusher:
            result = pusher.push(target, script)
    """

    def __init__(self, job: OnboardingJob):
        if job is None:
            raise BootstrapError("Pusher requires an OnboardingJob")
        self._job = job
        self._transport: Transport | None = None

    # ── context-manager sugar ─────────────────────────────────────────
    def __enter__(self) -> "Pusher":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._close_transport()

    # ── public surface ────────────────────────────────────────────────
    def push(self, target: BootstrapTarget, script: str) -> PushResult:
        """Run ``script`` against ``target`` ONCE and advance the job's status.

        Behaviour:

        * Acquires a transport from the registered factory for
          ``target.transport_kind``.
        * Invokes :meth:`Transport.push_script` exactly once.
        * Closes the transport in a ``finally`` block — the bootstrap
          channel is gone whether the push succeeded, raised, or returned
          ``ok=False``.
        * On success, advances ``OnboardingJob.status`` ``script_generated
          → pushed`` (§6.2) and commits. On failure, advances to
          ``failed``.

        The pusher commits its own status change so a caller that crashes
        afterwards doesn't leave the job stuck in ``script_generated``.
        """
        if not script:
            return self._fail("empty_script", raw="")

        # Status guard — only the legal incoming edge is honoured.
        if self._job.status != "script_generated":
            return self._fail(
                f"illegal_status:{self._job.status}",
                raw="pusher expects status=script_generated",
            )

        self._transport = _resolve_transport(target)
        try:
            tr = self._transport.push_script(script)
        except Exception as exc:  # noqa: BLE001 — transport-agnostic
            logger.exception("bootstrap push raised for job=%s", self._job.id)
            self._record_verify_report({
                "stage": "bootstrap_push",
                "ok": False,
                "error": "transport_exception",
                "exc_class": exc.__class__.__name__,
                # NOTE: do NOT include str(exc) — RouterOS APIs sometimes
                # echo the offending line which can include a leaked secret.
                "at": utcnow().isoformat() + "Z",
            })
            self._advance_to_failed()
            return PushResult(
                ok=False, job_id=self._job.id, new_status=self._job.status,
                error="transport_exception",
            )
        finally:
            self._close_transport()

        # Transport returned cleanly — interpret its verdict.
        if not tr.ok:
            self._record_verify_report({
                "stage": "bootstrap_push",
                "ok": False,
                "error": tr.error or "transport_failed",
                "output": tr.output,
                "latency_ms": tr.latency_ms,
                "at": utcnow().isoformat() + "Z",
            })
            self._advance_to_failed()
            return PushResult(
                ok=False, job_id=self._job.id, new_status=self._job.status,
                error=tr.error or "transport_failed", raw_output=tr.output,
                latency_ms=tr.latency_ms,
            )

        # Success path: script_generated → pushed, persist a tiny audit.
        self._record_verify_report({
            "stage": "bootstrap_push",
            "ok": True,
            "output": tr.output,
            "latency_ms": tr.latency_ms,
            "at": utcnow().isoformat() + "Z",
        })
        self._advance_to_pushed()
        return PushResult(
            ok=True, job_id=self._job.id, new_status=self._job.status,
            raw_output=tr.output, latency_ms=tr.latency_ms,
        )

    # ── private ───────────────────────────────────────────────────────
    def _close_transport(self) -> None:
        if self._transport is None:
            return
        try:
            self._transport.close()
        except Exception:  # noqa: BLE001 — closing must never raise out
            logger.exception(
                "bootstrap transport close() raised for job=%s — ignoring",
                self._job.id,
            )
        finally:
            self._transport = None

    def _advance_to_pushed(self) -> None:
        # The model's advance() guards the legality of the transition.
        self._job.advance("pushed")
        db.session.add(self._job)
        db.session.commit()

    def _advance_to_failed(self) -> None:
        # ``failed`` is reachable from every non-terminal state per the §6.2
        # graph; advance() will raise if the job is already terminal-success.
        try:
            self._job.advance("failed")
        except ValueError:
            # Already terminal (active) — nothing to record. Should never
            # happen during a push, but defend against test misuse.
            logger.warning(
                "cannot advance job=%s to failed from status=%s",
                self._job.id, self._job.status,
            )
            return
        db.session.add(self._job)
        db.session.commit()

    def _record_verify_report(self, payload: dict) -> None:
        # ``verify_report`` is a structured JSON column — we append a new
        # event to its ``events`` list so multiple stages (push, RADIUS
        # test, CoA reachability, …) accumulate side-by-side.
        report = self._job.verify_report or {}
        events = list(report.get("events", []))
        events.append(payload)
        report["events"] = events
        self._job.verify_report = report

    def _fail(self, error: str, *, raw: str) -> PushResult:
        # Early-fail path — runs before any transport allocation, so no
        # close() is needed. Still advances the job so the wizard's state
        # machine knows.
        self._record_verify_report({
            "stage": "bootstrap_push",
            "ok": False,
            "error": error,
            "output": raw,
            "at": utcnow().isoformat() + "Z",
        })
        self._advance_to_failed()
        return PushResult(
            ok=False, job_id=self._job.id, new_status=self._job.status,
            error=error, raw_output=raw,
        )


# ───────────────────────── convenience entry-point ─────────────────────────

def push_to_chr(job: OnboardingJob, target: BootstrapTarget, script: str) -> PushResult:
    """Thin functional wrapper that opens a :class:`Pusher`, runs one push,
    closes it, and returns the :class:`PushResult`. Equivalent to::

        with Pusher(job) as p:
            return p.push(target, script)
    """
    with Pusher(job) as pusher:
        return pusher.push(target, script)


__all__ = [
    "BootstrapError",
    "BootstrapTarget",
    "PushResult",
    "Pusher",
    "Transport",
    "TransportResult",
    "push_to_chr",
    "register_transport",
]
