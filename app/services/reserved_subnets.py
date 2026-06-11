"""Reserved-subnet guard — keep PPP/VPN client addressing away from wg-mgmt/data.

The fleet's control + data planes use two parallel /24 pools:

  * ``10.99.0.0/24`` — wg-mgmt (panel ↔ CHR control plane). Panel = .1, nodes from .11.
  * ``10.98.0.0/24`` — wg-data (proxy ↔ CHR RADIUS plane). Proxy = .1, nodes from .11.

These addresses are taken by the WireGuard tunnels and the RADIUS proxy.
A PPTP / SSTP / L2TP server pool that hands clients addresses inside
either subnet creates an address collision: the CHR will route RADIUS
toward its own PPP client instead of the wg-data peer, and the proxy
sees packets from an "unknown CHR IP" or never sees them at all
(the live ``chr-vpn-1`` outage of 2026-06).

This module is the single source of truth for "is this address /
range / CIDR reserved by the fleet?". Every PPP-pool / local-address
write path MUST call :func:`ensure_not_reserved` (or
:func:`assert_address_not_reserved`, :func:`assert_pool_range_not_reserved`)
before persisting the value.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable


#: The two reserved /24 pools. The proxy and the panel themselves take
#: ``.1`` in each, fleet CHR nodes are allocated from ``.11`` upward.
RESERVED_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.98.0.0/24"),  # wg-data
    ipaddress.IPv4Network("10.99.0.0/24"),  # wg-mgmt
)

#: Human-readable labels for the UI / error messages (Arabic).
RESERVED_LABELS_AR: dict[str, str] = {
    "10.98.0.0/24": "شبكة wg-data المحجوزة لنفق RADIUS بين الوكيل والـ CHR",
    "10.99.0.0/24": "شبكة wg-mgmt المحجوزة لقناة التحكم بين اللوحة والـ CHR",
}


class ReservedSubnetError(ValueError):
    """Raised when a configured address/range/CIDR overlaps a reserved fleet net."""


def _to_ip(value: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value.strip())
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ReservedSubnetError(f"عنوان IP غير صالح: {value!r}") from exc


def _to_network(value: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(value.strip(), strict=False)
    except (ipaddress.NetmaskValueError, ValueError) as exc:
        raise ReservedSubnetError(f"شبكة IP غير صالحة: {value!r}") from exc


def is_reserved_address(value: str) -> bool:
    """True iff the bare IPv4 address falls inside any reserved net."""
    try:
        ip = _to_ip(value)
    except ReservedSubnetError:
        return False
    return any(ip in net for net in RESERVED_NETWORKS)


def _ranges_in(value: str) -> Iterable[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    """Yield ``(first, last)`` for every comma-separated MikroTik-style range.

    Accepts ``"a.b.c.d-e.f.g.h"`` and bare ``"a.b.c.d"`` (single host) tokens
    separated by commas — the RouterOS ``/ip pool`` ``ranges`` shape. Empty
    or malformed tokens are skipped; the caller must defend against them
    with its own input validation if needed.
    """
    for token in (value or "").split(","):
        tok = token.strip()
        if not tok:
            continue
        if "-" in tok:
            start_s, _, end_s = tok.partition("-")
            try:
                first = _to_ip(start_s)
                last = _to_ip(end_s)
            except ReservedSubnetError:
                continue
            if int(last) < int(first):
                first, last = last, first
            yield first, last
        else:
            try:
                only = _to_ip(tok)
            except ReservedSubnetError:
                continue
            yield only, only


def is_reserved_range(value: str) -> bool:
    """True iff ANY address inside any range overlaps a reserved net."""
    for first, last in _ranges_in(value):
        first_i, last_i = int(first), int(last)
        for net in RESERVED_NETWORKS:
            net_lo, net_hi = int(net.network_address), int(net.broadcast_address)
            if first_i <= net_hi and last_i >= net_lo:
                return True
    return False


def is_reserved_network(value: str) -> bool:
    """True iff the CIDR overlaps a reserved net."""
    try:
        net = _to_network(value)
    except ReservedSubnetError:
        return False
    return any(net.overlaps(r) for r in RESERVED_NETWORKS)


def _reserved_hint() -> str:
    parts = [f"{n} ({RESERVED_LABELS_AR[str(n)]})" for n in RESERVED_NETWORKS]
    return " و ".join(parts)


def assert_address_not_reserved(value: str, *, field_label: str = "العنوان") -> str:
    """Validate a bare IPv4 address. Returns the stripped value or raises."""
    cleaned = (value or "").strip()
    if not cleaned:
        return cleaned
    if is_reserved_address(cleaned):
        raise ReservedSubnetError(
            f"{field_label}: العنوان {cleaned} يقع داخل شبكة محجوزة للأسطول "
            f"({_reserved_hint()}). اختر عنواناً خارج هذه الشبكات."
        )
    return cleaned


def assert_pool_range_not_reserved(value: str, *, field_label: str = "نطاق العناوين") -> str:
    """Validate a MikroTik ``ranges=`` value. Returns the stripped value or raises."""
    cleaned = (value or "").strip()
    if not cleaned:
        return cleaned
    if is_reserved_range(cleaned):
        raise ReservedSubnetError(
            f"{field_label}: النطاق {cleaned} يتقاطع مع شبكة محجوزة للأسطول "
            f"({_reserved_hint()}). استخدم نطاقاً خارج هذه الشبكات (مثل 10.10.0.10-10.10.0.250)."
        )
    return cleaned


def assert_network_not_reserved(value: str, *, field_label: str = "الشبكة") -> str:
    """Validate a CIDR. Returns the stripped value or raises."""
    cleaned = (value or "").strip()
    if not cleaned:
        return cleaned
    if is_reserved_network(cleaned):
        raise ReservedSubnetError(
            f"{field_label}: الشبكة {cleaned} تتقاطع مع شبكة محجوزة للأسطول "
            f"({_reserved_hint()}). استخدم CIDR خارج 10.98.0.0/24 و 10.99.0.0/24."
        )
    return cleaned


def ensure_not_reserved(
    *,
    address: str | None = None,
    pool_range: str | None = None,
    network: str | None = None,
    field_label: str = "القيمة",
) -> None:
    """One-call validator covering the three shapes a PPP-pool write may take."""
    if address is not None:
        assert_address_not_reserved(address, field_label=field_label)
    if pool_range is not None:
        assert_pool_range_not_reserved(pool_range, field_label=field_label)
    if network is not None:
        assert_network_not_reserved(network, field_label=field_label)


__all__ = [
    "RESERVED_NETWORKS",
    "RESERVED_LABELS_AR",
    "ReservedSubnetError",
    "is_reserved_address",
    "is_reserved_range",
    "is_reserved_network",
    "assert_address_not_reserved",
    "assert_pool_range_not_reserved",
    "assert_network_not_reserved",
    "ensure_not_reserved",
]
