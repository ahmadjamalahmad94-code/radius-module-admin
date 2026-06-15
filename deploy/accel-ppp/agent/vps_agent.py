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

STATUS: skeleton. The argv we build is best-effort and FLAGGED where it needs
lab validation. This module may move into the ``radius-module`` repo later
(design §1 — "subpackage inside radius-module if we co-locate"); it lives here
now so the one-time setup script can install something today.
"""
from __future__ import annotations

import argparse
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


def build_shaper_argv(spec: WireguardPeerSpec) -> list[list[str]]:
    """tc HTB commands for a per-peer ``rate_mbit`` cap on the wg interface.

    Egress shaping on the wg iface throttles traffic TOWARD the peer; the
    matching ingress policer is FLAGGED for lab validation (direction +
    classid allocation must be confirmed against the live kernel/iproute2).

    The classid is derived from the peer's last IPv4 octet for determinism;
    real deployment needs a collision-free allocator (lab-pending).
    """
    iface = spec.interface
    kbit = mbit_to_kbit(spec.rate_mbit)
    # Derive a stable minor id from the allowed IP (1..255). LAB-PENDING: a
    # proper allocator must guarantee uniqueness across concurrent peers.
    last = spec.allowed_ip.split("/")[0].split(".")[-1] if "." in spec.allowed_ip else "10"
    try:
        minor = max(1, min(255, int(last)))
    except ValueError:
        minor = 10
    classid = f"1:{minor}"
    handle = f"{minor}:"
    return [
        # Root qdisc (idempotent: 'replace' won't error if it already exists).
        ["tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb",
         "default", "9999"],
        # Per-peer class capped at the plan rate.
        ["tc", "class", "replace", "dev", iface, "parent", "1:", "classid", classid,
         "htb", "rate", f"{kbit}kbit", "ceil", f"{kbit}kbit"],
        # fq_codel under the class for fair queueing within the cap.
        ["tc", "qdisc", "replace", "dev", iface, "parent", classid, "handle", handle,
         "fq_codel"],
        # Filter peer traffic into the class by destination /32.
        ["tc", "filter", "replace", "dev", iface, "protocol", "ip", "parent", "1:",
         "prio", "1", "u32", "match", "ip", "dst", _cidr_for(spec.allowed_ip),
         "flowid", classid],
    ]


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


def build_certbot_argv(fqdn: str, email: str, *, staging: bool = False,
                       webroot: str = "") -> list[str]:
    """certbot HTTP-01 issuance argv. ``--keep-until-expiring`` makes re-runs
    idempotent (no needless reissue). ``--standalone`` binds :80 for the
    challenge (accel-ppp owns 443, not 80); pass ``webroot`` to use an existing
    server instead. ``--staging`` for dry-runs against LE staging."""
    argv = ["certbot", "certonly", "--non-interactive", "--agree-tos",
            "--keep-until-expiring", "-d", fqdn, "--email", email]
    if webroot:
        argv += ["--webroot", "-w", webroot]
    else:
        argv += ["--standalone"]
    if staging:
        argv += ["--staging"]
    return argv


# ── agent (binds the seam to the logic) ───────────────────────────────────--
class VpsAgent:
    def __init__(self, executor: CommandExecutor, resolver: Resolver | None = None) -> None:
        self._x = executor
        self._resolver = resolver

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
        """Add/update the WG peer, then apply its per-peer speed cap."""
        peer = self._run_all(build_wireguard_peer_argv(spec))
        if not peer.ok:
            return peer
        shaper = self._run_all(build_shaper_argv(spec))
        shaper.commands = peer.commands + shaper.commands
        return shaper

    def apply_shaper(self, spec: WireguardPeerSpec) -> AgentResult:
        return self._run_all(build_shaper_argv(spec))

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
                    timeout_s: float = 300, interval_s: float = 10,
                    staging: bool = False,
                    sleep: Callable[[float], None] = time.sleep,
                    monotonic: Callable[[], float] = time.monotonic) -> AgentResult:
        """Wait for DNS, then issue the cert (certbot HTTP-01). Non-fatal:

        - DNS never resolves to this VPS within ``timeout_s`` → return ok=False
          with an actionable detail, WITHOUT calling certbot (no pointless
          challenge that would just fail).
        - certbot itself fails → return ok=False with certbot's rc/stderr.

        The caller (setup script) treats a False result as a warning, not a
        hard boot failure — accel-ppp stays installed and the operator can fix
        DNS and re-run (idempotent)."""
        resolver = self._resolver or SystemResolver()
        wait = wait_for_dns(fqdn, expected_ip, resolver=resolver,
                            timeout_s=timeout_s, interval_s=interval_s,
                            sleep=sleep, monotonic=monotonic)
        if not wait.ok:
            return AgentResult(False, detail=f"DNS wait failed: {wait.detail}")
        argv = build_certbot_argv(fqdn, email, staging=staging)
        res = self._x.run(argv)
        if not res.ok:
            return AgentResult(False, commands=[argv],
                               detail=f"certbot failed (rc={res.returncode}): "
                                      f"{(res.stderr or res.stdout).strip()}")
        return AgentResult(True, commands=[argv], detail=f"cert issued for {fqdn}")

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


# ── CLI entrypoint (skeleton) ─────────────────────────────────────────────--
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HobeRadius VPS agent (skeleton)")
    parser.add_argument("--serve", action="store_true", help="run as a daemon (LAB-PENDING)")
    parser.add_argument("--wg-iface", default="wg-data")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list-sessions", action="store_true")
    # Cert automation (called by the setup script / certbot deploy-hook).
    parser.add_argument("--ensure-cert", action="store_true",
                        help="wait for DNS then issue the LE cert (certbot HTTP-01)")
    parser.add_argument("--reload-accel", action="store_true",
                        help="reload accel-ppp (certbot deploy-hook target)")
    parser.add_argument("--subdomain", default="", help="FQDN, e.g. client5.hoberadius.com")
    parser.add_argument("--vps-ip", default="", help="this VPS public IP the FQDN must resolve to")
    parser.add_argument("--email", default="", help="certbot registration email")
    parser.add_argument("--timeout", type=float, default=300.0, help="DNS-wait timeout (s)")
    parser.add_argument("--interval", type=float, default=10.0, help="DNS-wait poll interval (s)")
    parser.add_argument("--staging", action="store_true", help="use LE staging (dry-run)")
    args = parser.parse_args(argv)

    agent = VpsAgent(SystemExecutor(dry_run=args.dry_run))
    if args.reload_accel:
        res = agent.reload_accel_ppp()
        print(f"vps-agent reload-accel: {res.detail}")
        return 0 if res.ok else 1
    if args.ensure_cert:
        if not (args.subdomain and args.vps_ip and args.email):
            print("vps-agent --ensure-cert requires --subdomain, --vps-ip and --email")
            return 2
        res = agent.ensure_cert(args.subdomain, args.vps_ip, args.email,
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
        # LAB-PENDING: the daemon loop (poll the panel/bridge for peer specs,
        # reconcile WG peers + shapers, report sessions) is not implemented yet.
        print("vps-agent: --serve is a skeleton stub; nothing to do. Exiting cleanly.")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
