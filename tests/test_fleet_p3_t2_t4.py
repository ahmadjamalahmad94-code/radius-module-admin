"""CHR Fleet Phase 3 — P3-T2 + P3-T4 verification.

Covers:

* :mod:`fleet.registry.wg_keys`
    - generates a structurally valid Curve25519 / WireGuard keypair
      (44-char base64, 32 raw bytes, public is the derived public of the
      private — i.e. the keypair survives an export/import round-trip).
    - the public key matches WireGuard's own validator shape; ``repr`` does
      not leak the private half.
    - ``generate_keypair_with_vault`` parks the private key in the vault and
      returns only the public key + a ref — the plaintext is NOT returned.

* :mod:`fleet.registry.secrets_vault`
    - ``store_secret`` writes ONE row to ``fleet_chr_secrets`` with the
      ciphertext column, and the row never contains the plaintext.
    - a SELECT * over the table never returns the plaintext (defense-in-depth
      check: every column of every row is asserted to NOT contain the
      plaintext string).
    - ``retrieve_secret`` round-trips back to the original plaintext and
      stamps ``last_revealed_at``.
    - ``forget_secret`` deletes the row; ``forget_owner`` bulk-deletes.

* :mod:`fleet.registry.bootstrap_push`
    - happy path: a FAKE Transport returns ok=True → the job advances
      ``script_generated → pushed``; ``close()`` is called exactly once;
      ``verify_report`` records the stage.
    - sad path: Transport returns ok=False → the job advances to ``failed``
      with the error encoded into ``verify_report``; ``close()`` still
      called.
    - exception path: Transport raises → still closed exactly once; status
      → ``failed``; ``str(exc)`` is NOT included in the recorded report (so
      a RouterOS echo can't leak a secret).
    - empty-script early-fail does not even allocate a transport.
"""
from __future__ import annotations

import re

import pytest
from sqlalchemy import inspect, text

from app.extensions import db

# Import the models so they're on db.metadata before create_all().
from fleet.registry.models_chr import FleetChrNode, FleetProvider
from fleet.registry.models_onboarding import OnboardingJob

# The modules under test
from fleet.registry import bootstrap_push, secrets_vault, wg_keys


# ───────────────────────── shared fixtures ─────────────────────────

@pytest.fixture()
def job(app):
    """A draft OnboardingJob already advanced to script_generated.

    The bootstrap pusher only accepts that state — it's the legal
    incoming edge per §6.2.
    """
    j = OnboardingJob(status="draft", form_input={"name": "chr-test-1"})
    db.session.add(j)
    db.session.commit()
    j.advance("keys_generated")
    j.advance("script_generated")
    db.session.add(j)
    db.session.commit()
    return j


# ═════════════════════════════════════════════════════════════════════
# wg_keys
# ═════════════════════════════════════════════════════════════════════

def test_keypair_is_wg_format():
    kp = wg_keys.generate_keypair()
    # 44 chars including '=' padding, decodes to 32 raw bytes.
    assert len(kp.public_key) == wg_keys.WG_KEY_B64_LEN == 44
    assert len(kp.private_key) == 44
    assert wg_keys.is_valid_wg_key(kp.public_key)
    assert wg_keys.is_valid_wg_key(kp.private_key)
    # Round-trip: rederive the public from the private; must match.
    assert wg_keys.derive_public_key(kp.private_key) == kp.public_key


def test_repr_redacts_private_half():
    kp = wg_keys.generate_keypair()
    # An accidental log(kp) must not leak the private key.
    assert kp.private_key not in repr(kp)
    assert kp.private_key not in str(kp)
    assert "<redacted>" in repr(kp)


def test_two_generated_keys_differ_with_high_probability():
    a = wg_keys.generate_keypair()
    b = wg_keys.generate_keypair()
    assert a.private_key != b.private_key
    assert a.public_key != b.public_key


def test_is_valid_wg_key_rejects_obvious_garbage():
    for bad in [
        "",                                            # empty
        "not-base64",                                  # wrong length
        "A" * 43,                                      # one short
        "A" * 45,                                      # one long
        "!" + "A" * 43,                                # wrong charset
    ]:
        assert wg_keys.is_valid_wg_key(bad) is False, bad


def test_derive_public_key_rejects_malformed_input():
    with pytest.raises(wg_keys.WgKeyError):
        wg_keys.derive_public_key("not a key")


def test_generate_keypair_with_vault_never_returns_plaintext(app, monkeypatch):
    # Master key required to encrypt — wired by TestingConfig already.
    pub, ref = wg_keys.generate_keypair_with_vault(owner="onboarding:99")
    assert wg_keys.is_valid_wg_key(pub)
    assert isinstance(ref, secrets_vault.VaultRef)
    # The ref string is what gets stored on the owning record. It is opaque,
    # not the private key.
    assert not wg_keys.is_valid_wg_key(ref.ref)
    # The private key survives a round-trip via the vault.
    plain = secrets_vault.retrieve_secret(ref)
    assert wg_keys.is_valid_wg_key(plain)
    assert wg_keys.derive_public_key(plain) == pub


# ═════════════════════════════════════════════════════════════════════
# secrets_vault
# ═════════════════════════════════════════════════════════════════════

def test_chr_secrets_table_has_no_plaintext_columns(app):
    """The ``fleet_chr_secrets`` table must, by construction, carry no
    column named anything like ``plaintext`` / ``cleartext`` / ``secret``
    (other than ``ciphertext``). This is the schema-level proof that the
    vault refuses to even MODEL a plaintext column."""
    insp = inspect(db.engine)
    cols = {c["name"] for c in insp.get_columns("fleet_chr_secrets")}
    assert "ciphertext" in cols, "vault must persist ciphertext"
    # Anything that looks like a plaintext field is forbidden.
    forbidden = {
        c for c in cols
        if any(s in c.lower() for s in ("plaintext", "cleartext", "private_raw"))
    }
    assert not forbidden, f"plaintext-shaped columns leaked into schema: {forbidden}"


def test_store_and_retrieve_round_trip(app):
    ref = secrets_vault.store_secret(
        owner="chr:7", purpose="wg_mgmt",
        plaintext="super-secret-private-key", kind="wg_private_key",
    )
    assert isinstance(ref, secrets_vault.VaultRef)
    assert secrets_vault.has_secret(ref) is True

    plain = secrets_vault.retrieve_secret(ref)
    assert plain == "super-secret-private-key"

    # last_revealed_at gets stamped on read.
    snap = secrets_vault.describe_secret(ref)
    assert snap["last_revealed_at"] is not None
    assert snap["owner"] == "chr:7"
    assert snap["purpose"] == "wg_mgmt"
    assert snap["kind"] == "wg_private_key"


def test_raw_disk_state_never_contains_plaintext(app):
    """Defense-in-depth: scan every row in the table for the plaintext
    string. The Fernet ciphertext must be the only persisted form."""
    sentinel = "P3-T2-SENTINEL-{plain-text-must-not-leak}"
    secrets_vault.store_secret(
        owner="chr:scan", purpose="wg_mgmt",
        plaintext=sentinel, kind="wg_private_key",
    )

    # SELECT * — every column, every row.
    rows = list(db.session.execute(text("SELECT * FROM fleet_chr_secrets")).mappings())
    assert rows, "vault row must exist"
    for row in rows:
        for col, value in row.items():
            if value is None:
                continue
            assert sentinel not in str(value), (
                f"plaintext leaked into column {col!r}"
            )


def test_describe_never_returns_plaintext(app):
    ref = secrets_vault.store_secret(
        owner="chr:hide", purpose="wg_data", plaintext="DO-NOT-LEAK",
    )
    snap = secrets_vault.describe_secret(ref)
    # No key in the snapshot may contain the plaintext.
    assert all("DO-NOT-LEAK" not in str(v) for v in snap.values()), snap
    # Sanity: the snapshot DOES carry a masked preview of the ciphertext.
    assert snap["masked"] and "…" in snap["masked"]


def test_forget_secret_and_forget_owner_are_idempotent(app):
    r1 = secrets_vault.store_secret(owner="chr:9", purpose="wg_mgmt", plaintext="x1")
    r2 = secrets_vault.store_secret(owner="chr:9", purpose="wg_data", plaintext="x2")
    assert secrets_vault.has_secret(r1)
    assert secrets_vault.has_secret(r2)

    assert secrets_vault.forget_secret(r1) is True
    # Second call returns False (idempotent — no error).
    assert secrets_vault.forget_secret(r1) is False
    assert not secrets_vault.has_secret(r1)

    # Bulk delete the remaining one for owner=chr:9.
    n = secrets_vault.forget_owner("chr:9")
    assert n == 1
    assert not secrets_vault.has_secret(r2)
    # Idempotent: deleting an empty owner returns 0, no exception.
    assert secrets_vault.forget_owner("chr:9") == 0


def test_store_rejects_empty_plaintext(app):
    with pytest.raises(secrets_vault.VaultError):
        secrets_vault.store_secret(owner="chr:9", purpose="x", plaintext="")


def test_store_requires_master_key(app, monkeypatch):
    # Blank the master Fernet so encryption is impossible.
    monkeypatch.setitem(app.config, "WHATSAPP_FERNET_KEY", "")
    with pytest.raises(secrets_vault.VaultError):
        secrets_vault.store_secret(owner="chr:9", purpose="x", plaintext="y")


def test_retrieve_unknown_ref_raises(app):
    with pytest.raises(secrets_vault.VaultError):
        secrets_vault.retrieve_secret("vr_does_not_exist")


# ═════════════════════════════════════════════════════════════════════
# bootstrap_push
# ═════════════════════════════════════════════════════════════════════

class _FakeTransport:
    """Records every call so the test can assert ``close()`` discipline."""

    def __init__(self, *, ok: bool = True, output: str = "OK", error: str = "",
                 raise_on_push: Exception | None = None):
        self.calls: list[str] = []
        self.script_seen: str | None = None
        self.close_count = 0
        self._ok = ok
        self._output = output
        self._error = error
        self._raise = raise_on_push

    def push_script(self, script: str) -> bootstrap_push.TransportResult:
        self.calls.append("push_script")
        self.script_seen = script
        if self._raise is not None:
            raise self._raise
        return bootstrap_push.TransportResult(
            ok=self._ok, output=self._output, error=self._error, latency_ms=42,
        )

    def close(self) -> None:
        self.calls.append("close")
        self.close_count += 1


@pytest.fixture()
def fake_transport_factory():
    """Per-test registration of a fake transport, with teardown."""
    holder: list[_FakeTransport] = []

    def install(transport: _FakeTransport):
        bootstrap_push.register_transport(
            "fake", lambda target: transport
        )
        holder.append(transport)
        return transport

    yield install
    bootstrap_push.register_transport("fake", None)


def _target() -> bootstrap_push.BootstrapTarget:
    return bootstrap_push.BootstrapTarget(
        host="203.0.113.55", port=8729, username="admin",
        password="one-time-bootstrap-pass", transport_kind="fake",
    )


def test_bootstrap_target_repr_redacts_password():
    t = _target()
    # An accidental log(target) must not leak the bootstrap password.
    assert "one-time-bootstrap-pass" not in repr(t)
    assert "one-time-bootstrap-pass" not in str(t)
    assert "<redacted>" in repr(t)


def test_happy_path_advances_to_pushed(app, job, fake_transport_factory):
    fake = fake_transport_factory(_FakeTransport(ok=True, output="ok-from-routeros"))

    result = bootstrap_push.push_to_chr(job, _target(), "/system identity set name=x")

    assert result.ok is True
    assert result.new_status == "pushed"
    assert result.raw_output == "ok-from-routeros"
    # The transport was opened once, pushed once, closed once. Idempotent close.
    assert fake.calls == ["push_script", "close"]
    assert fake.close_count == 1
    # verify_report carries the success event.
    fresh = db.session.get(OnboardingJob, job.id)
    assert fresh.status == "pushed"
    events = fresh.verify_report["events"]
    assert events[-1]["stage"] == "bootstrap_push"
    assert events[-1]["ok"] is True


def test_failed_push_advances_to_failed_and_records_error(app, job, fake_transport_factory):
    fake = fake_transport_factory(
        _FakeTransport(ok=False, output="bad-creds", error="auth_failed")
    )

    result = bootstrap_push.push_to_chr(job, _target(), "/system identity set name=x")

    assert result.ok is False
    assert result.error == "auth_failed"
    assert result.new_status == "failed"
    # Even on failure, the transport was closed exactly once.
    assert fake.close_count == 1
    fresh = db.session.get(OnboardingJob, job.id)
    assert fresh.status == "failed"
    last = fresh.verify_report["events"][-1]
    assert last["ok"] is False and last["error"] == "auth_failed"


def test_exception_path_closes_transport_and_does_not_leak_exc_message(app, job, fake_transport_factory):
    boom = RuntimeError("RouterOS-echo with secret one-time-bootstrap-pass")
    fake = fake_transport_factory(_FakeTransport(raise_on_push=boom))

    result = bootstrap_push.push_to_chr(job, _target(), "/system identity set name=x")

    assert result.ok is False
    assert result.error == "transport_exception"
    assert result.new_status == "failed"
    assert fake.close_count == 1, "transport must close exactly once on exception path"
    fresh = db.session.get(OnboardingJob, job.id)
    last = fresh.verify_report["events"][-1]
    # The recorded report MUST NOT include str(exc) — the exception text
    # contains a secret RouterOS could echo back.
    assert "one-time-bootstrap-pass" not in last.get("output", "")
    assert "one-time-bootstrap-pass" not in last.get("exc_class", "")
    # The exception class name (a safe identifier) IS recorded.
    assert last["exc_class"] == "RuntimeError"


def test_empty_script_short_circuits_without_transport(app, job, fake_transport_factory):
    fake = fake_transport_factory(_FakeTransport(ok=True))

    result = bootstrap_push.push_to_chr(job, _target(), "")

    assert result.ok is False
    assert result.error == "empty_script"
    # No transport involvement when the script is empty.
    assert fake.calls == []
    assert fake.close_count == 0
    # Job still advances to failed so the wizard state is honest.
    fresh = db.session.get(OnboardingJob, job.id)
    assert fresh.status == "failed"


def test_pusher_rejects_unknown_transport_kind(app, job):
    target = bootstrap_push.BootstrapTarget(
        host="203.0.113.55", transport_kind="totally-not-registered",
    )
    with pytest.raises(bootstrap_push.BootstrapError):
        bootstrap_push.push_to_chr(job, target, "/system identity set name=x")


def test_pusher_rejects_illegal_starting_status(app, fake_transport_factory):
    # A draft job MUST NOT skip straight to bootstrap — the state machine
    # only allows script_generated → pushed.
    fake_transport_factory(_FakeTransport(ok=True))
    j = OnboardingJob(status="draft", form_input={})
    db.session.add(j); db.session.commit()

    result = bootstrap_push.push_to_chr(j, _target(), "/system identity set name=x")
    assert result.ok is False
    assert result.error.startswith("illegal_status:draft")


# ═════════════════════════════════════════════════════════════════════
# create_app smoke (anchors the "import app; app.create_app() OK" req)
# ═════════════════════════════════════════════════════════════════════

def test_create_app_boots_with_phase3_modules_loaded(app):
    """Importing the three Phase-3 modules must not break the app boot."""
    # If we got the ``app`` fixture, create_app() already returned cleanly.
    # Sanity-check that the vault table is wired on the metadata.
    tables = set(inspect(db.engine).get_table_names())
    assert "fleet_chr_secrets" in tables
