"""«تغيير عنوان الإنترنت» — ONE merged catalog service, TWO live backends.

Surface/contract invariants for the merge of the two historical IP-change cards
(``ip_change_vpn`` tunnel + ``public_ip_change`` server-public-IP) into a single
customer-facing service with a METHOD choice. Provisioning/routing is covered in
test_ipchange_full_provision.py.
"""
from __future__ import annotations

from app.extensions import db
from app.models import ServiceCatalogItem
from app.services.customer_control import (
    DEFAULT_PAID_SERVICES,
    IP_CHANGE_DEFAULT_METHOD,
    IP_CHANGE_LEGACY_PUBLIC_KEY,
    IP_CHANGE_METHOD_SERVER_PUBLIC_IP,
    IP_CHANGE_METHOD_TUNNEL,
    IP_CHANGE_SERVICE_KEY,
    clean_ip_change_method,
    seed_service_catalog,
    service_catalog_items,
    service_spec_fields,
)
from app.services.provider_service_gate import PROVIDER_TO_GATE
from app.services.trial_plan import TRIAL_PAID_SERVICES


def test_single_ip_change_catalog_card(app):
    with app.app_context():
        keys = [i.service_key for i in service_catalog_items()]
        assert IP_CHANGE_SERVICE_KEY in keys                 # the ONE surviving card
        assert IP_CHANGE_LEGACY_PUBLIC_KEY not in keys        # no orphan second card
        item = ServiceCatalogItem.query.filter_by(service_key=IP_CHANGE_SERVICE_KEY).one()
        assert item.name_ar == "تغيير عنوان الإنترنت"
        assert item.price_monthly is not None                 # per-Mbps seed preserved


def test_seed_retires_legacy_public_ip_change_row(app):
    """A legacy install that still has the second card gets it pruned on seed."""
    with app.app_context():
        db.session.add(ServiceCatalogItem(
            service_key=IP_CHANGE_LEGACY_PUBLIC_KEY, name="legacy", name_ar="legacy",
            description="legacy", category="network", default_enabled=False, sort_order=12))
        db.session.commit()
        seed_service_catalog()
        db.session.commit()
        assert ServiceCatalogItem.query.filter_by(service_key=IP_CHANGE_LEGACY_PUBLIC_KEY).first() is None


def test_method_choice_in_spec_fields(app):
    with app.app_context():
        fields = service_spec_fields(IP_CHANGE_SERVICE_KEY)
    by_key = {f["key"]: f for f in fields}
    assert "method" in by_key
    method = by_key["method"]
    assert method["type"] == "choice"
    assert method["default"] == IP_CHANGE_DEFAULT_METHOD
    assert {o["value"] for o in method["options"]} == {
        IP_CHANGE_METHOD_TUNNEL, IP_CHANGE_METHOD_SERVER_PUBLIC_IP}
    # the per-Mbps spec fields are gated to the tunnel method only
    for k in ("download_mbps", "upload_mbps", "max_vpn_users", "quota_gb"):
        assert by_key[k]["show_when"]["in"] == [IP_CHANGE_METHOD_TUNNEL], k


def test_clean_ip_change_method():
    assert clean_ip_change_method("tunnel") == IP_CHANGE_METHOD_TUNNEL
    assert clean_ip_change_method("server_public_ip") == IP_CHANGE_METHOD_SERVER_PUBLIC_IP
    assert clean_ip_change_method("") == IP_CHANGE_DEFAULT_METHOD          # default = tunnel
    assert clean_ip_change_method("bogus") == IP_CHANGE_DEFAULT_METHOD


def test_both_backends_still_gate_to_network():
    # Both keys still resolve to the «الشبكة» gate so BOTH backends stay live.
    assert PROVIDER_TO_GATE[IP_CHANGE_SERVICE_KEY] == "network"
    assert PROVIDER_TO_GATE[IP_CHANGE_LEGACY_PUBLIC_KEY] == "network"


def test_one_paid_ip_change_key():
    assert IP_CHANGE_SERVICE_KEY in DEFAULT_PAID_SERVICES
    assert IP_CHANGE_LEGACY_PUBLIC_KEY not in DEFAULT_PAID_SERVICES
    assert IP_CHANGE_SERVICE_KEY in TRIAL_PAID_SERVICES
    assert IP_CHANGE_LEGACY_PUBLIC_KEY not in TRIAL_PAID_SERVICES
