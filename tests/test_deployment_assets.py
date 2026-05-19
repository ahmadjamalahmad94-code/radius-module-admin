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
    assert "LICENSE_CHECK_ALLOW_UNSIGNED=0" in env
    assert "LICENSE_CHECK_SIGNATURE_REQUIRED=1" in env
    assert "replace-with-" in env
    assert "admin12345" not in env


def test_deployment_scripts_compile():
    py_compile.compile(str(ROOT / "deploy/scripts/health_check.py"), doraise=True)
    py_compile.compile(str(ROOT / "deploy/scripts/backup_sqlite.py"), doraise=True)
