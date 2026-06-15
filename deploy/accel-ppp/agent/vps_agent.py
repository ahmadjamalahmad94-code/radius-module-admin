#!/usr/bin/env python3
"""HobeRadius VPS agent — accel-ppp DATA connections (2c, SKELETON).

Runs on the customer's RADIUS VPS. Its jobs (design §1, §5):

  1. Apply a WireGuard DATA peer (RouterOS v7 path) — ``wg set …``.
  2. Apply a per-peer speed cap (5 Mbit default) via ``tc`` HTB on the wg iface.
  3. Read live sessions from accel-ppp (``accel-cmd show sessions``).
  4. Issue + renew the SSTP TLS cert (certbot HTTP-01) — with a bounded
     wait until the subdomain's DNS A record resolves to THIS VPS first, so a
     first-boot/cloud-init propagation lag doesn't fail the install.
  5. Reload accel-ppp so it picks up a fresh cert (the certbot deploy-hook
     calls this).

DESIGN — TESTABLE SEAM
======================
Every real OS call goes through a :class:`CommandExecutor`; every DNS lookup
goes through a :class:`Resolver`. The agent's logic (building argv, parsing
accel-cmd output, the DNS-wait loop, Mbit→tc rate) is PURE and unit-tested with
a :class:`FakeExecutor` + :class:`FakeResolver` (injected ``sleep``/``clock`` so
tests never actually wait); the production :class:`SystemExecutor` /
:class:`SystemResolver` are the only things that touch the OS/network. CI never
shells out or hits the network.

STATUS: the reconcile loop, collision-free classid allocator, cert challenge
selection (HTTP-01 / DNS-01 fallback), and WG-port clash check are implemented
+ unit-tested with fakes. The genuinely live-only knobs stay FLAGGED LAB-PENDING
(exact Filter-Id shaper form, Session-Octets-Limit/227 support, Disconnect NAS
source IP, and the peer-source HMAC auth + exact tc ingress direction). This
module may move into the ``radius-module`` repo later (design §1).
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol


# ── command seam ────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandExecutor(Protocol):
    """The single OS seam. Tests provide a fake; prod uses SystemExecutor."""
    def run(self, argv: list[str]) -> CommandResult: ...


class SystemExecutor:
    """Real executor — the ONLY code that touches the OS. Not exercised in CI."""
    def __init__(self, *, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def run(self, argv: list[str]) -> CommandResult:
        if self.dry_run:
            print("DRY-RUN:", " ".join(shlex.quote(a) for a in argv))
            return CommandResult(0, "", "")
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)


class FakeExecutor:
    """Records argv and replays canned output keyed by the first 2 tokens.

    Used by the unit tests — assert on ``.calls`` and seed ``.responses``."""
    def __init__(self, responses: dict[str, CommandResult] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.responses = responses or {}

    def run(self, argv: list[str]) -> CommandResult:
        self.calls.append(list(argv))
        key = " ".join(argv[:2])
        return self.responses.get(key, CommandResult(0, "", ""))


# ── DNS seam ─────────────────────────────────────────────────────────────────
class Resolver(Protocol):
    """The single DNS seam. Tests provide a fake; prod uses SystemResolver."""
    def resolve(self, hostname: str, *, ipv6: bool = False) -> list[str]: ...


class SystemResolver:
    """Real resolver — the ONLY code that hits DNS. Not exercised in CI."""
    def resolve(self, hostname: str, *, ipv6: bool = False) -> list[str]:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        try:
            infos = socket.getaddrinfo(hostname, None, family=family)
        except socket.gaierror:
            return []
        return sorted({info[4][0] for info in infos})


class FakeResolver:
    """Replays canned answers per call (last entry repeats). Used by tests to
    simulate DNS propagation: e.g. [[], ["9.9.9.9"], ["1.2.3.4"]]."""
    def __init__(self, sequence: list[list[str]] | None = None) -> None:
        self._seq = list(sequence or [])
        self.calls = 0

    def resolve(self, hostname: str, *, ipv6: bool = False) -> list[str]:
        self.calls += 1
        if not self._seq:
            return []
        idx = min(self.calls - 1, len(self._seq) - 1)
        return list(self._seq[idx])


# ── port-80 reachability seam (certbot challenge selection) ──────────────────
class Port80Prober(Protocol):
    """Seam for "can certbot HTTP-01 work here?" Tests provide a fake."""
    def is_open(self, host: str, *, port: int = 80, timeout: float = 3.0) -> bool: ...


class SystemPort80Prober:
    """Best-effort TCP connect probe. NOTE: a self-probe can't fully prove
    EXTERNAL reachability (a firewall upstream may still block inbound) — the
    live RUNBOOK validates that. We use it as the ``auto`` heuristic only."""
    def is_open(self, host: str, *, port: int = 80, timeout: float = 3.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False


class FakePort80Prober:
    def __init__(self, open_: bool) -> None:
        self._open = open_
    def is_open(self, host: str, *, port: int = 80, timeout: float = 3.0) -> bool:
        return self._open


# ── domain types ──────────────────────────────────────────────────────────--
#: Locked default per-connection speed (design §0: 5–10 Mbit). 5 Mbit = floor.
DEFAULT_RATE_MBIT = 5


@dataclass(frozen=True)
class WireguardPeerSpec:
    public_key: str
    allowed_ip: str                 # the single /32 (or /128) handed to this peer
    interface: str = "wg-data"
    rate_mbit: int = DEFAULT_RATE_MBIT
    preshared_key: str = ""


@dataclass(frozen=True)
class Session:
    username: str
    ip: str
    iface: str
    type: str = ""                  # sstp | pptp | l2tp | …
    rx_bytes: int = 0
    tx_bytes: int = 0


@dataclass
class AgentResult:
    ok: bool
    detail: str = ""
    commands: list[list[str]] = field(default_factory=list)


# ── pure helpers (the heart of the unit tests) ───────────────────────────────
def _cidr_for(allowed_ip: str) -> str:
    """Return ``allowed_ip`` as a host CIDR. Bare IPv4 → /32, IPv6 → /128;
    an explicit prefix is left untouched."""
    ip = (allowed_ip or "").strip()
    if "/" in ip:
        return ip
    return f"{ip}/128" if ":" in ip else f"{ip}/32"


def build_wireguard_peer_argv(spec: WireguardPeerSpec) -> list[list[str]]:
    """argv to add/update one WG peer. ``wg set`` is idempotent — re-applying
    the same peer just updates it, so no remove-first dance is needed."""
    argv = ["wg", "set", spec.interface, "peer", spec.public_key,
            "allowed-ips", _cidr_for(spec.allowed_ip)]
    cmds = [argv]
    # A preshared key can't be passed inline; wg reads it from a file path.
    # The setup/daemon writes it out first — flagged for the real impl.
    if spec.preshared_key:
        # WireGuard pubkeys are base64 (contain '/' and '+'), so derive a
        # filesystem-safe, collision-resistant slug for the .psk path — a raw
        # '/' from the key would otherwise create a bogus subdir and the write
        # (and the subsequent wg read) would fail.
        psk_path = f"/run/wg-{_safe_slug(spec.public_key)}.psk"
        cmds.insert(0, ["sh", "-c", f"umask 077; printf %s {shlex.quote(spec.preshared_key)} "
                                    f"> {psk_path}"])
        argv += ["preshared-key", psk_path]
    return cmds


def _safe_slug(public_key: str) -> str:
    """Collision-resistant, filesystem-safe slug from a WG public key — a short
    hex digest, so two keys sharing a base64 prefix don't collide on the same
    .psk filename and '/'/'+' never leak into the path."""
    import hashlib
    return hashlib.sha256((public_key or "").encode("utf-8")).hexdigest()[:16]


def mbit_to_kbit(rate_mbit: int) -> int:
    return max(1, int(rate_mbit)) * 1000


# ── collision-free classid allocator ─────────────────────────────────────────
#: tc classids are written ``major:minor`` where BOTH numbers are HEX. The htb
#: root reserves a default class; we use 0x9999 for it and keep it out of the
#: allocatable space. Minor range is 1..0xffff.
HTB_DEFAULT_MINOR = 0x9999
MIN_MINOR = 0x1
MAX_MINOR = 0xFFFF


class ClassidAllocator:
    """Hands each peer a UNIQUE tc class minor, with release/reuse.

    Replaces the old last-octet scheme (10.20.0.5 and 10.20.1.5 collided on
    minor 5). Keyed by the peer's WireGuard public key (stable, unique). The
    smallest free minor is reused after a ``release`` so the space doesn't
    leak under churn. Deterministic for a given allocation order; the reconcile
    loop allocates in sorted-pubkey order so a fresh process is reproducible."""

    def __init__(self, reserved: set[int] | None = None) -> None:
        self._assigned: dict[str, int] = {}
        self._used: set[int] = set(reserved or {HTB_DEFAULT_MINOR})

    def allocate(self, key: str) -> int:
        if key in self._assigned:
            return self._assigned[key]
        for n in range(MIN_MINOR, MAX_MINOR + 1):
            if n not in self._used:
                self._used.add(n)
                self._assigned[key] = n
                return n
        raise RuntimeError("tc classid space exhausted")

    def minor_for(self, key: str) -> int | None:
        return self._assigned.get(key)

    def release(self, key: str) -> int | None:
        n = self._assigned.pop(key, None)
        if n is not None:
            self._used.discard(n)
        return n

    def __contains__(self, key: str) -> bool:
        return key in self._assigned

    @property
    def assigned(self) -> dict[str, int]:
        return dict(self._assigned)


def _shaper_match(allowed_ip: str) -> tuple[str, str]:
    """(protocol, u32-match-keyword) for the peer's address family. IPv6 needs
    ``protocol ipv6`` + ``match ip6`` — ``protocol ip`` silently fails for v6."""
    if ":" in (allowed_ip or ""):
        return "ipv6", "ip6"
    return "ip", "ip"


def build_root_qdisc_argv(iface: str) -> list[str]:
    """The htb root qdisc. Installed ONCE per interface via ``ensure_root_qdisc``
    (an `add` only when absent) — never ``replace``, which would wipe the child
    classes of peers already shaped."""
    return ["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb",
            "default", format(HTB_DEFAULT_MINOR, "x")]


def build_peer_shaper_argv(spec: WireguardPeerSpec, minor: int) -> list[list[str]]:
    """Per-peer tc class + leaf qdisc + filter for ``minor`` (a unique classid
    minor from :class:`ClassidAllocator`). Uses ``replace`` so re-applying ONE
    peer is idempotent and never disturbs other peers. The filter ``prio`` is
    the (unique) minor so the peer's filter can be deleted in isolation."""
    iface = spec.interface
    kbit = mbit_to_kbit(spec.rate_mbit)
    classid = f"1:{minor:x}"
    handle = f"{minor:x}:"
    prio = str(minor)
    proto, match_kw = _shaper_match(spec.allowed_ip)
    return [
        # Per-peer class capped at the plan rate.
        ["tc", "class", "replace", "dev", iface, "parent", "1:", "classid", classid,
         "htb", "rate", f"{kbit}kbit", "ceil", f"{kbit}kbit"],
        # fq_codel under the class for fair queueing within the cap.
        ["tc", "qdisc", "replace", "dev", iface, "parent", classid, "handle", handle,
         "fq_codel"],
        # Filter this peer's traffic into the class by destination host route.
        ["tc", "filter", "replace", "dev", iface, "protocol", proto, "parent", "1:",
         "prio", prio, "u32", "match", match_kw, "dst", _cidr_for(spec.allowed_ip),
         "flowid", classid],
    ]


def build_peer_shaper_delete_argv(iface: str, minor: int) -> list[list[str]]:
    """Tear down ONE peer's shaper (filter by its unique prio, then class).
    Targeted — leaves every other peer's shaping intact."""
    classid = f"1:{minor:x}"
    return [
        ["tc", "filter", "del", "dev", iface, "parent", "1:", "prio", str(minor)],
        ["tc", "class", "del", "dev", iface, "classid", classid],
    ]


def build_wireguard_peer_remove_argv(public_key: str, iface: str) -> list[str]:
    """Remove a WG peer. ``wg set … peer KEY remove`` is idempotent."""
    return ["wg", "set", iface, "peer", public_key, "remove"]


#: accel-cmd's ``show sessions`` is column-formatted. We parse the common
#: columns; the exact header set is build-dependent → LAB-PENDING. We accept a
#: header line and map by column name so reordering doesn't break us.
def parse_sessions(raw: str) -> list[Session]:
    """Parse ``accel-cmd show sessions`` output into :class:`Session` rows.

    Tolerant: blank/garbage lines are skipped. Maps columns by the header row
    when present (``ifname``/``username``/``ip``/``type``/``rx-bytes``/``tx-bytes``)."""
    lines = [ln for ln in (raw or "").splitlines() if ln.strip()]
    if not lines:
        return []
    # Header detection: accel-cmd prints a header containing 'username'.
    header_idx = next((i for i, ln in enumerate(lines) if "username" in ln.lower()), None)
    sessions: list[Session] = []
    if header_idx is not None:
        cols = [c.strip().lower() for c in re.split(r"\s*\|\s*|\s{2,}", lines[header_idx]) if c.strip()]
        for ln in lines[header_idx + 1:]:
            cells = [c.strip() for c in re.split(r"\s*\|\s*|\s{2,}", ln) if c.strip()]
            if len(cells) < 2:
                continue
            row = dict(zip(cols, cells))
            sessions.append(Session(
                username=row.get("username", ""),
                ip=row.get("ip", "") or row.get("ip-address", ""),
                iface=row.get("ifname", "") or row.get("iface", ""),
                type=row.get("type", ""),
                rx_bytes=_to_int(row.get("rx-bytes", row.get("rx", "0"))),
                tx_bytes=_to_int(row.get("tx-bytes", row.get("tx", "0"))),
            ))
        return sessions
    # No header — fall back to whitespace columns: ifname username ip [type].
    for ln in lines:
        cells = ln.split()
        if len(cells) < 3:
            continue
        sessions.append(Session(iface=cells[0], username=cells[1], ip=cells[2],
                                type=cells[3] if len(cells) > 3 else ""))
    return sessions


def _to_int(value: str) -> int:
    try:
        return int(re.sub(r"[^0-9]", "", str(value)) or 0)
    except ValueError:
        return 0


# ── pure: DNS wait + certbot argv ─────────────────────────────────────────--
@dataclass(frozen=True)
class DnsWaitResult:
    ok: bool
    attempts: int
    resolved: list[str]
    detail: str = ""


def wait_for_dns(fqdn: str, expected_ip: str, *, resolver: Resolver,
                 timeout_s: float = 300, interval_s: float = 10,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic) -> DnsWaitResult:
    """Poll until ``fqdn`` resolves to ``expected_ip`` (this VPS) or timeout.

    The panel creates the A record (2c) when the customer is added with the VPS
    IP — which is BEFORE the VPS exists — so normally this returns on the first
    attempt. The bounded retry only covers propagation lag on a fast first boot.

    Always attempts at least once. Never raises: on timeout it returns
    ``ok=False`` with an actionable ``detail`` so the caller logs + continues
    (cert issuance is non-fatal to the boot). ``sleep``/``monotonic`` are
    injectable so tests run instantly."""
    ipv6 = ":" in (expected_ip or "")
    start = monotonic()
    attempts = 0
    resolved: list[str] = []
    while True:
        attempts += 1
        resolved = resolver.resolve(fqdn, ipv6=ipv6)
        if expected_ip in resolved:
            return DnsWaitResult(True, attempts, resolved,
                                 f"{fqdn} -> {expected_ip} after {attempts} attempt(s)")
        if monotonic() - start >= timeout_s:
            return DnsWaitResult(
                False, attempts, resolved,
                f"{fqdn} did not resolve to {expected_ip} within {timeout_s:.0f}s "
                f"(last seen: {resolved or 'NXDOMAIN'}). Confirm the panel created "
                f"the Cloudflare A record for this customer's VPS IP.")
        sleep(interval_s)


#: Cert challenge modes (setup knob CERT_CHALLENGE).
CHALLENGE_HTTP01 = "http01"
CHALLENGE_DNS01 = "dns01"
CHALLENGE_AUTO = "auto"


def select_challenge(mode: str, *, port80_open: bool) -> str:
    """Resolve the effective challenge. ``auto`` picks HTTP-01 when port 80 is
    reachable, else DNS-01. Explicit modes pass through. Unknown → auto."""
    m = (mode or CHALLENGE_AUTO).strip().lower()
    if m in (CHALLENGE_HTTP01, CHALLENGE_DNS01):
        return m
    return CHALLENGE_HTTP01 if port80_open else CHALLENGE_DNS01


def build_certbot_argv(fqdn: str, email: str, *, challenge: str = CHALLENGE_HTTP01,
                       staging: bool = False, webroot: str = "",
                       cf_credentials_path: str = "") -> list[str]:
    """certbot issuance argv. ``--keep-until-expiring`` makes re-runs idempotent.

    - ``http01`` (default): ``--standalone`` binds :80 for the challenge
      (accel-ppp owns 443, not 80); pass ``webroot`` to use a running server.
    - ``dns01``: ``--dns-cloudflare`` with a credentials INI (needs the CF token
      on the VPS — see the README security trade-off). Works when :80 is
      firewalled. ``--staging`` for dry-runs against LE staging."""
    argv = ["certbot", "certonly", "--non-interactive", "--agree-tos",
            "--keep-until-expiring", "-d", fqdn, "--email", email]
    if challenge == CHALLENGE_DNS01:
        argv += ["--dns-cloudflare", "--dns-cloudflare-credentials", cf_credentials_path]
    elif webroot:
        argv += ["--webroot", "-w", webroot]
    else:
        argv += ["--standalone"]
    if staging:
        argv += ["--staging"]
    return argv


# ── desired-peer contract (reuse the panel's /wg-peers shape) ────────────────
@dataclass(frozen=True)
class DesiredPeer:
    public_key: str
    allowed_ip: str
    rate_mbit: int = DEFAULT_RATE_MBIT
    name: str = ""


def parse_desired_peers(payload: dict, *, default_rate_mbit: int = DEFAULT_RATE_MBIT) -> list[DesiredPeer]:
    """Parse the documented top-level ``peers`` contract (app/api/proxy_api.py
    /wg-peers): ``{peers:[{name, public_key, allowed_ips:[...], endpoint,
    rate_mbit?}]}``. Each peer's first ``allowed_ips`` entry is the host route.
    Peers missing a public_key or allowed_ips are skipped (the panel surfaces
    that as a failed sync stage, not a silent gap)."""
    out: list[DesiredPeer] = []
    for p in (payload or {}).get("peers", []) or []:
        if not isinstance(p, dict):
            continue
        key = str(p.get("public_key", "")).strip()
        allowed = p.get("allowed_ips") or []
        if not key or not allowed:
            continue
        rate = p.get("rate_mbit")
        try:
            rate = int(rate) if rate is not None else default_rate_mbit
        except (TypeError, ValueError):
            rate = default_rate_mbit
        out.append(DesiredPeer(public_key=key, allowed_ip=str(allowed[0]).strip(),
                               rate_mbit=rate, name=str(p.get("name", ""))))
    return out


class PeerSource(Protocol):
    """Seam that yields the desired DATA wg-peer set. Tests provide a fake;
    prod fetches the panel contract over HTTP."""
    def fetch_desired(self) -> list[DesiredPeer]: ...


class StaticPeerSource:
    """Fixed desired set — used by tests and for a file-driven daemon."""
    def __init__(self, peers: list[DesiredPeer]) -> None:
        self._peers = list(peers)
    def fetch_desired(self) -> list[DesiredPeer]:
        return list(self._peers)


class HttpPeerSource:
    """Fetches + parses the panel's wg-peers contract. The ``fetch_json``
    callable is injected so tests mock the HTTP entirely.

    LAB-PENDING: the exact endpoint path + the ``X-Proxy-Token`` HMAC auth must
    match the panel's live contract; supply ``fetch_json`` that performs the
    signed GET. The contract PARSING (parse_desired_peers) is implemented +
    tested here."""
    def __init__(self, url: str, fetch_json: Callable[[str], dict],
                 *, default_rate_mbit: int = DEFAULT_RATE_MBIT) -> None:
        self._url = url
        self._fetch_json = fetch_json
        self._default_rate = default_rate_mbit

    def fetch_desired(self) -> list[DesiredPeer]:
        payload = self._fetch_json(self._url)
        return parse_desired_peers(payload, default_rate_mbit=self._default_rate)


@dataclass
class ReconcileResult:
    ok: bool
    in_sync: bool = False
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    detail: str = ""


# ── pure: listening-UDP-port parsing + free-port pick (WG clash check) ───────
def parse_listening_udp_ports(ss_output: str) -> set[int]:
    """Extract listening UDP local ports from ``ss -lun`` output. Tolerant of
    column layout: we take the local-address column's trailing ``:PORT``."""
    ports: set[int] = set()
    for ln in (ss_output or "").splitlines():
        s = ln.strip()
        if not s or s.lower().startswith(("netid", "state", "recv-q")):
            continue
        for tok in s.split():
            # local addr looks like 0.0.0.0:51820 / [::]:51820 / *:51820
            m = re.search(r":(\d{1,5})$", tok)
            if m:
                try:
                    ports.add(int(m.group(1)))
                except ValueError:
                    pass
    return ports


def pick_free_port(desired: int, used: set[int], *, max_tries: int = 20) -> int | None:
    """Return ``desired`` if free, else the next free port scanning upward.
    ``None`` if none free within ``max_tries`` (caller emits a clear error)."""
    for n in range(desired, desired + max_tries):
        if 1 <= n <= 65535 and n not in used:
            return n
    return None


# ── agent (binds the seam to the logic) ───────────────────────────────────--
class VpsAgent:
    def __init__(self, executor: CommandExecutor, resolver: Resolver | None = None,
                 prober: Port80Prober | None = None,
                 allocator: ClassidAllocator | None = None) -> None:
        self._x = executor
        self._resolver = resolver
        self._prober = prober
        self._alloc = allocator or ClassidAllocator()
        # Peers THIS process has applied (safe-remove set) + their last desired
        # spec (so an unchanged peer is a true no-op next tick).
        self._managed: dict[str, DesiredPeer] = {}

    def _run_all(self, cmds: list[list[str]]) -> AgentResult:
        ran: list[list[str]] = []
        for argv in cmds:
            ran.append(argv)
            res = self._x.run(argv)
            if not res.ok:
                return AgentResult(False, detail=f"{' '.join(argv)} -> rc={res.returncode} {res.stderr}".strip(),
                                   commands=ran)
        return AgentResult(True, commands=ran)

    def apply_wireguard_peer(self, spec: WireguardPeerSpec) -> AgentResult:
        """Add/update the WG peer, then apply its per-peer speed cap (with a
        collision-free classid). Ensures the root qdisc exists first."""
        peer = self._run_all(build_wireguard_peer_argv(spec))
        if not peer.ok:
            return peer
        self.ensure_root_qdisc(spec.interface)
        minor = self._alloc.allocate(spec.public_key)
        shaper = self._run_all(build_peer_shaper_argv(spec, minor))
        shaper.commands = peer.commands + shaper.commands
        return shaper

    def apply_shaper(self, spec: WireguardPeerSpec) -> AgentResult:
        minor = self._alloc.allocate(spec.public_key)
        return self._run_all(build_peer_shaper_argv(spec, minor))

    # ── reconcile daemon ────────────────────────────────────────────────
    def list_wg_peers(self, iface: str) -> list[str]:
        """Public keys currently configured on ``iface`` (``wg show … peers``)."""
        res = self._x.run(["wg", "show", iface, "peers"])
        if not res.ok:
            return []
        return [ln.strip() for ln in (res.stdout or "").splitlines() if ln.strip()]

    def ensure_root_qdisc(self, iface: str) -> AgentResult:
        """Idempotently ensure the htb root qdisc exists. We ADD only when
        absent (checking ``tc qdisc show``) — never ``replace``, which would
        destroy the child classes of peers already shaped."""
        show = self._x.run(["tc", "qdisc", "show", "dev", iface])
        if show.ok and "htb" in (show.stdout or "") and "1:" in (show.stdout or ""):
            return AgentResult(True, detail="root qdisc present")
        return self._run_all([build_root_qdisc_argv(iface)])

    def remove_peer(self, public_key: str, iface: str) -> AgentResult:
        """Remove a WG peer + its shaper, and free its classid. Used by the
        reconciler for peers IT previously added that are no longer desired."""
        cmds = [build_wireguard_peer_remove_argv(public_key, iface)]
        minor = self._alloc.minor_for(public_key)
        if minor is not None:
            cmds += build_peer_shaper_delete_argv(iface, minor)
        res = self._run_all(cmds)
        if res.ok:
            self._alloc.release(public_key)
        return res

    def reconcile_once(self, source: PeerSource, iface: str = "wg-data") -> ReconcileResult:
        """One reconcile tick. Idempotent + safe-by-default:

        - fetch the desired peer set (transient fetch error → ok=False, no crash);
        - ADD/UPDATE each desired peer (skip when unchanged → true no-op in sync);
        - REMOVE only peers THIS process added that are no longer desired —
          NEVER an operator-added peer (one not in our managed set);
        - per-peer command failures are recorded, the loop continues (non-fatal).
        """
        try:
            desired = source.fetch_desired()
        except Exception as exc:  # noqa: BLE001 — a flaky fetch must not kill the daemon
            return ReconcileResult(ok=False, detail=f"peer fetch failed: {type(exc).__name__}: {exc}")

        desired_by_key = {p.public_key: p for p in desired}
        current = set(self.list_wg_peers(iface))
        added: list[str] = []
        removed: list[str] = []
        errors: list[str] = []

        # ADD / UPDATE — apply only when the peer is missing or its spec changed.
        for key in sorted(desired_by_key):
            peer = desired_by_key[key]
            if key in current and self._managed.get(key) == peer:
                continue  # already in sync → no-op
            spec = WireguardPeerSpec(public_key=key, allowed_ip=peer.allowed_ip,
                                     interface=iface, rate_mbit=peer.rate_mbit)
            res = self.apply_wireguard_peer(spec)
            if res.ok:
                self._managed[key] = peer
                added.append(key)
            else:
                errors.append(key)

        # REMOVE — only managed peers (added by us) that are no longer desired.
        for key in sorted(set(self._managed) - set(desired_by_key)):
            res = self.remove_peer(key, iface)
            if res.ok:
                self._managed.pop(key, None)
                removed.append(key)
            else:
                errors.append(key)

        return ReconcileResult(ok=not errors, in_sync=not added and not removed,
                               added=added, removed=removed, errors=errors)

    def serve(self, source: PeerSource, *, iface: str = "wg-data",
              interval_s: float = 30, max_ticks: int | None = None,
              sleep: Callable[[float], None] = time.sleep) -> list[ReconcileResult]:
        """Run the reconcile loop. ``max_ticks`` bounds it for tests (None =
        forever in production). Each tick is non-fatal; the loop never raises."""
        results: list[ReconcileResult] = []
        tick = 0
        while max_ticks is None or tick < max_ticks:
            results.append(self.reconcile_once(source, iface))
            tick += 1
            if max_ticks is not None and tick >= max_ticks:
                break
            sleep(interval_s)
        return results

    def check_wg_port(self, desired_port: int, *, pick_next: bool = False) -> tuple[bool, int | None, str]:
        """Detect a WG data-port clash via ``ss -lun``.

        Returns ``(free, port_to_use, detail)``:
        - free=True  → ``desired_port`` is available (port_to_use == desired).
        - free=False, pick_next=False → clash; port_to_use=None; actionable detail.
        - free=False, pick_next=True  → port_to_use = next free port (or None)."""
        res = self._x.run(["ss", "-lun"])
        used = parse_listening_udp_ports(res.stdout) if res.ok else set()
        if desired_port not in used:
            return True, desired_port, f"udp/{desired_port} is free"
        if not pick_next:
            return (False, None,
                    f"udp/{desired_port} is already in use (ss -lun). Choose a free "
                    f"WG_DATA_PORT that doesn't clash with the mgmt/data WG already "
                    f"on this box, or re-run with port auto-pick.")
        chosen = pick_free_port(desired_port + 1, used)
        if chosen is None:
            return False, None, f"no free UDP port found near {desired_port}"
        return False, chosen, f"udp/{desired_port} in use; next free is udp/{chosen}"

    def list_active_sessions(self) -> list[Session]:
        res = self._x.run(["accel-cmd", "show", "sessions"])
        if not res.ok:
            return []
        return parse_sessions(res.stdout)

    def renew_cert(self) -> AgentResult:
        """Trigger certbot renew. The certbot deploy-hook (installed by the
        setup script) reloads accel-ppp; we run renew and let the hook fire."""
        return self._run_all([["certbot", "renew", "--quiet"]])

    def ensure_cert(self, fqdn: str, expected_ip: str, email: str, *,
                    challenge: str = CHALLENGE_AUTO, cf_credentials_path: str = "",
                    timeout_s: float = 300, interval_s: float = 10,
                    staging: bool = False,
                    sleep: Callable[[float], None] = time.sleep,
                    monotonic: Callable[[], float] = time.monotonic) -> AgentResult:
        """Issue the cert. Picks the ACME challenge, then issues. Non-fatal:

        Challenge selection (``challenge=auto`` default): probe port 80 → use
        HTTP-01 if reachable, else fall back to DNS-01 (Cloudflare). Explicit
        ``http01``/``dns01`` override the probe.

        - HTTP-01: the A record must point HERE, so we wait for DNS first; on
          timeout return ok=False WITHOUT calling certbot.
        - DNS-01: validates a TXT record via the Cloudflare plugin, so the A
          record need not resolve to us yet — we skip the wait. Requires
          ``cf_credentials_path`` (the CF token INI on the VPS).

        Always non-fatal: a False result is a warning to the caller, never a
        hard boot failure (accel-ppp stays installed; fix + re-run is idempotent)."""
        prober = self._prober or SystemPort80Prober()
        port80_open = prober.is_open(expected_ip) if challenge == CHALLENGE_AUTO else False
        mode = select_challenge(challenge, port80_open=port80_open)

        if mode == CHALLENGE_DNS01 and not cf_credentials_path:
            return AgentResult(False, detail=(
                "DNS-01 selected (port 80 unreachable or forced) but no Cloudflare "
                "credentials file — set CF_DNS_CREDENTIALS / CERT_CHALLENGE. "
                "See README security trade-off."))

        if mode == CHALLENGE_HTTP01:
            resolver = self._resolver or SystemResolver()
            wait = wait_for_dns(fqdn, expected_ip, resolver=resolver,
                                timeout_s=timeout_s, interval_s=interval_s,
                                sleep=sleep, monotonic=monotonic)
            if not wait.ok:
                return AgentResult(False, detail=f"DNS wait failed: {wait.detail}")

        argv = build_certbot_argv(fqdn, email, challenge=mode, staging=staging,
                                  cf_credentials_path=cf_credentials_path)
        res = self._x.run(argv)
        if not res.ok:
            return AgentResult(False, commands=[argv],
                               detail=f"certbot ({mode}) failed (rc={res.returncode}): "
                                      f"{(res.stderr or res.stdout).strip()}")
        return AgentResult(True, commands=[argv], detail=f"cert issued for {fqdn} via {mode}")

    def reload_accel_ppp(self) -> AgentResult:
        """Reload accel-ppp so it serves a fresh cert. Tries graceful reload
        first, falls back to a full restart only if both reloads fail. Invoked
        by the certbot deploy-hook on every renewal."""
        attempts = [["accel-cmd", "reload"],
                    ["systemctl", "reload", "accel-ppp"],
                    ["systemctl", "restart", "accel-ppp"]]
        ran: list[list[str]] = []
        for argv in attempts:
            ran.append(argv)
            if self._x.run(argv).ok:
                return AgentResult(True, commands=ran, detail=f"reloaded via {' '.join(argv)}")
        return AgentResult(False, commands=ran, detail="all reload methods failed")


def _urllib_fetch_json(url: str, *, token: str = "", timeout: float = 15.0) -> dict:
    """Minimal GET→JSON for the live peer source. LAB-PENDING: the panel's
    /wg-peers contract is authed with an X-Proxy-Token HMAC; wire that exact
    signing here before live use. The CONTRACT PARSING is already tested."""
    from urllib.request import Request, urlopen
    headers = {"Accept": "application/json"}
    if token:
        headers["X-Proxy-Token"] = token  # LAB-PENDING: replace with HMAC scheme
    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator-owned URL
        return json.loads(resp.read().decode("utf-8") or "{}")


# ── CLI entrypoint ─────────────────────────────────────────────────────────--
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HobeRadius VPS agent")
    parser.add_argument("--serve", action="store_true", help="run the reconcile daemon")
    parser.add_argument("--wg-iface", default="wg-data")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list-sessions", action="store_true")
    # Cert automation (called by the setup script / certbot deploy-hook).
    parser.add_argument("--ensure-cert", action="store_true",
                        help="select challenge, (wait for DNS,) issue the LE cert")
    parser.add_argument("--reload-accel", action="store_true",
                        help="reload accel-ppp (certbot deploy-hook target)")
    parser.add_argument("--check-wg-port", type=int, default=0,
                        help="check the WG data UDP port is free; exit 1 if in use")
    parser.add_argument("--subdomain", default="", help="FQDN, e.g. client5.hoberadius.com")
    parser.add_argument("--vps-ip", default="", help="this VPS public IP the FQDN must resolve to")
    parser.add_argument("--email", default="", help="certbot registration email")
    parser.add_argument("--challenge", default=CHALLENGE_AUTO,
                        choices=[CHALLENGE_AUTO, CHALLENGE_HTTP01, CHALLENGE_DNS01],
                        help="ACME challenge (auto probes port 80)")
    parser.add_argument("--cf-credentials", default="",
                        help="Cloudflare credentials INI for DNS-01")
    parser.add_argument("--timeout", type=float, default=300.0, help="DNS-wait timeout (s)")
    parser.add_argument("--interval", type=float, default=10.0,
                        help="DNS-wait poll / reconcile interval (s)")
    parser.add_argument("--staging", action="store_true", help="use LE staging (dry-run)")
    parser.add_argument("--peer-source-url", default="", help="panel wg-peers contract URL")
    parser.add_argument("--peer-source-token", default="", help="X-Proxy-Token for the peer source")
    args = parser.parse_args(argv)

    agent = VpsAgent(SystemExecutor(dry_run=args.dry_run))
    if args.reload_accel:
        res = agent.reload_accel_ppp()
        print(f"vps-agent reload-accel: {res.detail}")
        return 0 if res.ok else 1
    if args.check_wg_port:
        free, port, detail = agent.check_wg_port(args.check_wg_port)
        print(f"vps-agent check-wg-port: {detail}")
        return 0 if free else 1
    if args.ensure_cert:
        if not (args.subdomain and args.vps_ip and args.email):
            print("vps-agent --ensure-cert requires --subdomain, --vps-ip and --email")
            return 2
        res = agent.ensure_cert(args.subdomain, args.vps_ip, args.email,
                                challenge=args.challenge, cf_credentials_path=args.cf_credentials,
                                timeout_s=args.timeout, interval_s=args.interval,
                                staging=args.staging)
        print(f"vps-agent ensure-cert: {res.detail}")
        # Exit 1 on failure so the caller can warn; the caller MUST NOT treat
        # this as a hard boot failure (cert is non-fatal — design decision).
        return 0 if res.ok else 1
    if args.list_sessions:
        for s in agent.list_active_sessions():
            print(f"{s.username}\t{s.ip}\t{s.iface}\t{s.type}")
        return 0
    if args.serve:
        if not args.peer_source_url:
            print("vps-agent --serve requires --peer-source-url (the panel wg-peers contract)")
            return 2
        source = HttpPeerSource(
            args.peer_source_url,
            lambda u: _urllib_fetch_json(u, token=args.peer_source_token))
        print(f"vps-agent: reconcile daemon on {args.wg_iface}, every {args.interval:.0f}s")
        # max_ticks=None → run forever (systemd restarts on failure).
        agent.serve(source, iface=args.wg_iface, interval_s=args.interval, max_ticks=None)
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
