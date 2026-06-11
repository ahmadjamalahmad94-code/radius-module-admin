"""fleet.sync — zero-touch fleet onboarding + auto peer sync.

This package closes the manual-WireGuard gap that made adding a CHR a
three-place hand-peering chore and let the panel-key drift (the
``panel_key_mismatch`` incident) go silent. It is built around three ideas:

1. **Key stability** — the panel wg-mgmt keypair is the single stable source
   of truth. It is NEVER regenerated except by an explicit super-admin action,
   and when that happens every node is flagged ``needs_reimport`` and its
   script is re-rendered with the CURRENT panel pubkey (:mod:`fleet.sync.keys`).

2. **Auto peer registration** — the panel already knows every CHR's pubkeys,
   so onboarding/enabling a node (a) adds the CHR's wg-mgmt pubkey as a peer on
   the panel host (:mod:`fleet.sync.panel_peers`, applied via a scoped root
   helper, safe-by-default when absent) and (b) publishes the CHR's wg-data
   pubkey for the proxy agent to apply (:mod:`fleet.sync.proxy_peers`, served by
   ``GET /api/proxy/wg-peers``).

3. **Live staged progress** — a real sync-job state machine
   (:mod:`fleet.sync.models` / :mod:`fleet.sync.stages` / :mod:`fleet.sync.service`)
   drives a per-node, eight-stage progress view that reflects ACTUAL state by
   calling the existing troubleshoot / wg-verify / routing-table checks. No
   fake progress: every stage is a real probe.

Nothing here regenerates keys, weakens the frozen ``/api/proxy/routing-table``
contract, or performs a privileged action unless the operator has run the
one-time documented installer (``deploy/zero_touch/install_wg_helper.sh``).
"""
