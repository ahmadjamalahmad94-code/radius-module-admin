"""Shared fixtures/helpers for the zero-touch sync tests."""
from __future__ import annotations

import pytest

from app.extensions import db


def _pk(seed: str) -> str:
    """A syntactically valid 44-char base64 WireGuard pubkey for tests."""
    body = (seed * 43)[:43]
    return body + "="


def make_provider(name: str = "P1"):
    from fleet.registry.models_chr import FleetProvider
    prov = FleetProvider(name=name, cost_model="open", price_per_tb=0)
    db.session.add(prov)
    db.session.flush()
    return prov


def make_node(provider, name, *, octet, mgmt_pub=None, data_pub=None,
              enabled=True, drain=False, status="provisioning", public_ip=None):
    from fleet.registry.models_chr import FleetChrNode
    node = FleetChrNode(
        provider_id=provider.id,
        name=name,
        public_ip=public_ip or f"203.0.113.{octet}",
        wg_mgmt_ip=f"10.99.0.{octet}",
        wg_mgmt_pubkey=mgmt_pub if mgmt_pub is not None else _pk(f"m{octet}"),
        wg_data_pubkey=data_pub if data_pub is not None else _pk(f"d{octet}"),
        max_sessions=100,
        link_speed_mbps=1000,
        enabled=enabled,
        drain=drain,
        status=status,
    )
    db.session.add(node)
    db.session.flush()
    return node


def set_full_infra():
    """Populate all REQUIRED fleet-infra settings so script bindings pass."""
    from fleet.registry import infra_settings as ifs
    ifs.set_panel_pubkey(_pk("panel"))
    ifs.set_panel_endpoint("panel.example.com:51820")
    ifs.set_proxy_pubkey(_pk("proxy"))
    ifs.set_proxy_endpoint("proxy.example.com:51821")
    ifs.set_chr_shared_secret("x" * 32)


@pytest.fixture()
def zt(app):
    """App context + a couple of convenience helpers bound to the test DB."""
    return app
