"""fleet.ui — admin web pages for the CHR fleet (dashboard + onboarding wizard).

Owned by Phase 3 / group D (this agent). Other Phase-3 groups own:

  * ``fleet.registry.routes_chr``  — CRUD JSON API (this group, see sibling).
  * ``fleet.registry.routes_onboarding`` — onboarding state-machine API
    (POST jobs, advance state, render+push the unified RouterOS script).
    The wizard frontend in this package POSTS to that endpoint; it does NOT
    bypass it by calling the registry CRUD directly.
"""
