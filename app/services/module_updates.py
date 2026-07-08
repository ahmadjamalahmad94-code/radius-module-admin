"""Per-customer OPT-IN self-update feed for the customer RADIUS module.

The provider PUBLISHES an available ``ModuleRelease`` (version + Arabic
changelog + mandatory/min_version + optional targeting). Customer instances
poll ``GET /api/integration/hoberadius/update/latest`` (signed, guarded) and
their OWN panel decides whether to install — this layer only ADVERTISES.

Design notes:
- "Latest applicable" = the highest **semver** among published releases that
  target the customer, tie-broken by ``released_at`` then id. We sort by parsed
  semver (not string/date alone) so 1.10.0 correctly beats 1.9.0.
- The running version each customer reports is captured on every signed
  integration call (``LicenseCheck.version``); we surface it read-only on the
  customer page as «على أحدث إصدار» / «إصدار قديم».
- No forced push: ``mandatory`` is advisory metadata only.
"""
from __future__ import annotations

import re
from typing import Any

from ..extensions import db
from ..models import Customer, LicenseCheck, ModuleRelease, utcnow

#: A tolerant semver-ish pattern: MAJOR[.MINOR[.PATCH]] with an optional
#: -prerelease and +build. We require a leading digit so free-text can't be
#: published as a "version".
_SEMVER_RE = re.compile(
    r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-.]([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


class ModuleUpdateError(ValueError):
    """Validation error surfaced to the provider on publish (clear message)."""


def parse_semver(version: str | None) -> tuple[int, int, int, int, str]:
    """Parse into a sortable key. Release > prerelease of the same core.

    Returns ``(major, minor, patch, is_release, prerelease)`` where
    ``is_release`` is 1 for a plain release and 0 when a ``-prerelease`` suffix
    is present, so ``1.2.0`` sorts ABOVE ``1.2.0-rc1``. Unparseable input sorts
    lowest as ``(-1, 0, 0, 0, "")``.
    """
    if not version:
        return (-1, 0, 0, 0, "")
    m = _SEMVER_RE.match(str(version))
    if not m:
        return (-1, 0, 0, 0, "")
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    pre = m.group(4) or ""
    is_release = 0 if pre else 1
    return (major, minor, patch, is_release, pre)


def is_valid_version(version: str | None) -> bool:
    return bool(version) and _SEMVER_RE.match(str(version)) is not None


def clean_version(version: str | None, *, field: str = "الإصدار") -> str:
    v = str(version or "").strip()
    if not v:
        raise ModuleUpdateError(f"{field} مطلوب.")
    if not is_valid_version(v):
        raise ModuleUpdateError(f"{field} يجب أن يكون رقم إصدار صحيحاً مثل 1.4.2.")
    return v[:40]


def compare_versions(a: str | None, b: str | None) -> int:
    """-1 / 0 / +1 for a<b / a==b / a>b by semver (ignoring build metadata)."""
    ka, kb = parse_semver(a)[:4], parse_semver(b)[:4]
    return (ka > kb) - (ka < kb)


# ─────────────────────────── provider-side CRUD ───────────────────────────

def list_releases() -> list[ModuleRelease]:
    """All releases, newest-first for the admin publish page."""
    return (
        ModuleRelease.query
        .order_by(ModuleRelease.released_at.desc(), ModuleRelease.id.desc())
        .all()
    )


def get_release(release_id: int) -> ModuleRelease | None:
    return db.session.get(ModuleRelease, int(release_id))


def publish_release(
    *,
    version: str,
    changelog_md: str = "",
    released_at: Any = None,
    mandatory: bool = False,
    min_version: str = "",
    published: bool = True,
    target_all: bool = True,
    target_customer_ids: list[int] | None = None,
    created_by: int | None = None,
) -> ModuleRelease:
    """Create a new advertised release. Validates version + optional min_version."""
    v = clean_version(version)
    minv = str(min_version or "").strip()
    if minv and not is_valid_version(minv):
        raise ModuleUpdateError("الحد الأدنى للإصدار يجب أن يكون رقم إصدار صحيحاً مثل 1.0.0.")
    row = ModuleRelease(
        version=v,
        changelog_md=str(changelog_md or ""),
        released_at=released_at or utcnow(),
        mandatory=bool(mandatory),
        min_version=minv[:40],
        published=bool(published),
        target_all=bool(target_all),
        created_by=created_by,
    )
    row.target_customer_ids = [] if target_all else (target_customer_ids or [])
    db.session.add(row)
    db.session.flush()
    return row


def set_published(release: ModuleRelease, published: bool) -> ModuleRelease:
    release.published = bool(published)
    db.session.flush()
    return release


def delete_release(release: ModuleRelease) -> None:
    db.session.delete(release)


# ─────────────────────────── customer-facing read ─────────────────────────

#: Defensive cap on how many missed releases we fold into one feed response,
#: so a customer that's been offline for years can't trigger a giant payload.
_MAX_FEED_RELEASES = 50


def applicable_published_releases(customer: Customer) -> list[ModuleRelease]:
    """All PUBLISHED releases advertised to this customer, highest-semver first.

    Tie-broken by ``released_at`` then id (all deterministic), so the head is
    always the single "latest" and the list reads newest→oldest.
    """
    candidates = [
        r for r in ModuleRelease.query.filter_by(published=True).all()
        if r.applies_to_customer(customer.id)
    ]
    candidates.sort(
        key=lambda r: (parse_semver(r.version), r.released_at or utcnow(), r.id),
        reverse=True,
    )
    return candidates


def latest_release_for_customer(customer: Customer) -> ModuleRelease | None:
    """The single highest-semver PUBLISHED release advertised to this customer.

    Returns ``None`` when nothing published applies → the endpoint answers
    ``{"version": null}`` and the customer shows no update.
    """
    candidates = applicable_published_releases(customer)
    return candidates[0] if candidates else None


def releases_above(customer: Customer, current_version: str = "") -> list[ModuleRelease]:
    """Published, applicable releases STRICTLY newer than ``current_version``.

    Newest-first. When ``current_version`` is empty/unparseable (a fresh or
    never-reported instance) every applicable release counts as "missed", so the
    caller sees the full backlog. Capped at ``_MAX_FEED_RELEASES``.
    """
    applicable = applicable_published_releases(customer)
    cur = (current_version or "").strip()
    if cur and is_valid_version(cur):
        applicable = [r for r in applicable if compare_versions(r.version, cur) > 0]
    return applicable[:_MAX_FEED_RELEASES]


def build_update_feed(customer: Customer, current_version: str = "") -> dict[str, Any]:
    """The full self-update feed the endpoint returns for one customer.

    Supports SKIPPED releases: a customer on 1.0.0 who missed 1.1/1.2/1.3 gets
    the LATEST (1.3.0) at the top PLUS the CUMULATIVE changelog of everything
    above their current version, so their dialog shows all they missed — not
    just the newest release notes.

    Shape (nothing above current → ``{"version": null}``):
        {
          "version": "1.3.0",              # the latest applicable release
          "released_at": "..Z",
          "mandatory": true,               # true if ANY missed release is mandatory
          "min_version": "1.0.0" | null,   # hard floor to jump straight to latest
          "changelog_md": "<concatenated notes, newest-first>",
          "releases": [                    # each missed release, newest-first
            {"version": "1.3.0", "released_at": "..Z", "changelog_md": "..", "mandatory": false},
            ...
          ]
        }
    """
    above = releases_above(customer, current_version)
    if not above:
        # Either nothing published applies, or the caller is already at/above
        # the latest → no update to advertise.
        return {"version": None}
    latest = above[0]
    releases = [
        {
            "version": r.version,
            "released_at": r.released_at_iso(),
            "changelog_md": r.changelog_md or "",
            "mandatory": bool(r.mandatory),
        }
        for r in above
    ]
    # Flattened convenience changelog (newest-first). The structured ``releases``
    # list is the preferred render source; this is a fallback for simple dialogs.
    # A single missed release yields exactly its own notes (no separator added).
    cumulative_md = "\n\n---\n\n".join(
        r.changelog_md for r in above if (r.changelog_md or "").strip()
    )
    return {
        "version": latest.version,
        "released_at": releases[0]["released_at"],
        # Mandatory if the customer skipped ANY mandatory release in the span —
        # the jump is then effectively mandatory (still opt-in on the customer).
        "mandatory": any(r.mandatory for r in above),
        "min_version": (latest.min_version or "") or None,
        "changelog_md": cumulative_md,
        "releases": releases,
    }


def customer_reported_version(customer: Customer) -> str:
    """The customer instance's last-reported running version ("" if unknown).

    Sourced from the newest ``LicenseCheck`` (every signed integration call
    carries ``version``). Read-only — for the «على أحدث إصدار» status surface.
    """
    row = (
        LicenseCheck.query
        .filter_by(customer_id=customer.id)
        .order_by(LicenseCheck.checked_at.desc())
        .first()
    )
    return (row.version or "").strip() if row is not None else ""


def customer_update_status(customer: Customer) -> dict[str, Any]:
    """Read-only per-customer update state for the customer 360 page.

    ``state`` ∈ {"unknown", "up_to_date", "outdated", "no_release"}:
      • no_release  — nothing published applies to this customer.
      • unknown     — no running version reported by the instance yet.
      • up_to_date  — reported version ≥ latest advertised.
      • outdated    — a newer version is advertised than what's running.
    """
    latest = latest_release_for_customer(customer)
    current = customer_reported_version(customer)
    if latest is None:
        return {"state": "no_release", "current_version": current or "",
                "latest_version": "", "mandatory": False}
    if not current:
        return {"state": "unknown", "current_version": "",
                "latest_version": latest.version, "mandatory": bool(latest.mandatory)}
    up_to_date = compare_versions(current, latest.version) >= 0
    return {
        "state": "up_to_date" if up_to_date else "outdated",
        "current_version": current,
        "latest_version": latest.version,
        "mandatory": bool(latest.mandatory),
    }
