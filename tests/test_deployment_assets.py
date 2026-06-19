from __future__ import annotations

import py_compile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_deployment_assets_use_production_entrypoint_and_proxy_headers():
    service = read("deploy/systemd/hoberadius-license-panel.service.example")
    nginx = read("deploy/nginx/hoberadius-license-panel.conf.example")
    production_requirements = read("requirements-production.txt")

    assert '"wsgi:app"' in service
    assert "--workers 1" in service
    assert "EnvironmentFile=/etc/hoberadius-license-panel/license-panel.env" in service
    assert "gunicorn" in production_requirements
    assert "proxy_set_header X-Forwarded-For" in nginx
    assert "proxy_set_header X-Forwarded-Proto" in nginx
    assert "client_max_body_size 128k" in nginx


def test_deployment_env_keeps_required_production_safety_flags():
    env = read("deploy/env/license-panel.env.example")

    assert "LICENSE_PANEL_ENV=production" in env
    assert "SESSION_COOKIE_SECURE=1" in env
    assert "TRUST_PROXY_HEADERS=1" in env
    # Legacy LICENSE_CHECK_ALLOW_UNSIGNED / SIGNATURE_REQUIRED knobs retired
    # with the bearer-only link contract — they must NOT reappear in the
    # template (silent re-introduction would be a regression).
    assert "LICENSE_CHECK_ALLOW_UNSIGNED" not in env
    assert "LICENSE_CHECK_SIGNATURE_REQUIRED" not in env
    assert "LICENSE_CHECK_HMAC_SECRET" not in env
    assert "replace-with-" in env
    assert "admin12345" not in env


def test_deployment_scripts_compile():
    py_compile.compile(str(ROOT / "deploy/scripts/health_check.py"), doraise=True)
    py_compile.compile(str(ROOT / "deploy/scripts/backup_sqlite.py"), doraise=True)


def test_accel_setup_configures_forwarding_and_nat_egress():
    """The DATA BRAS must enable IPv4 forwarding + a MASQUERADE for the
    subscriber pool, else subscribers get a pool IP but NO internet."""
    s = read("deploy/accel-ppp/setup-radius-vps.sh")
    assert "net.ipv4.ip_forward=1" in s
    assert "-j MASQUERADE" in s
    assert "POOL_CIDR" in s
    # WAN interface auto-detected from the default route (override-able).
    assert "ip -4 route show default" in s
    assert "WAN_IFACE" in s


def test_accel_setup_opens_vpn_ports_surgically():
    """Inbound opens for the VPN ports (80/443/1723+GRE) — ADD-only."""
    s = read("deploy/accel-ppp/setup-radius-vps.sh")
    assert "open_tcp 443" in s          # SSTP
    assert "open_tcp 80" in s           # certbot HTTP-01
    assert "open_tcp 1723" in s         # PPTP control
    assert "-p gre -j ACCEPT" in s      # PPTP GRE


def test_accel_setup_firewall_is_lockout_safe():
    """SAFETY: the script must NEVER flush, set a default-DROP policy, or block
    SSH — those are the classic production self-lockout footguns. It only ADDs
    ACCEPT rules (guarded by -C for idempotency)."""
    s = read("deploy/accel-ppp/setup-radius-vps.sh")
    # no flush / no default-deny / no ufw reset
    assert "iptables -F" not in s
    assert "-P INPUT DROP" not in s
    assert "-P FORWARD DROP" not in s
    assert "ufw --force reset" not in s
    assert "ufw default deny" not in s
    # SSH (22) must never be dropped/rejected by this script
    assert "--dport 22 -j DROP" not in s
    assert "--dport 22 -j REJECT" not in s
    # idempotency guard present
    assert "-C INPUT" in s
    # reboot-safe oneshot unit (re-applies without iptables-persistent prompt)
    assert "hoberadius-accel-net.service" in s
