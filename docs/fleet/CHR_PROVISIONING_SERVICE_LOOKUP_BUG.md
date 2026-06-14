# CHR Provisioning — `/ip service get [find name=...]` Multi-Match Bug

**Branch landed in:** `fix/script-service-get-guard-foreach`
**Incident date (live):** 2026-06-14
**CHR affected:** `chr-vpn-2`
**Test backstop:** `tests/fleet_p3/test_script_service_get_guard.py`

---

## Symptom

The owner's manual `/import` of a freshly-regenerated provisioning script
halted partway through the §12 rollback-validation block with:

```
Script Error: invalid internal item number (/ip/service/get; line 1100)
```

Because the halt happened **before** the rollback-cancel line below,
the 3-minute self-lockout fired and the entire import was reverted.
The CHR sat in its pre-script state with no diagnostic trail beyond
the one log line above.

## Initial (wrong) diagnosis

The first fix (commit `e4b680f`, branch `fix/script-service-get-guard`)
assumed the offending line:

```rsc
:local winboxAddr [/ip service get [find name=winbox] address]
```

failed because `[find name=winbox]` returned an **empty** ref. The fix
length-guarded it:

```rsc
:local wbSvc [/ip service find name="winbox"]
:if ([:len $wbSvc] > 0) do={
    :do { :set winboxAddr [/ip service get $wbSvc address] } on-error={}
}
```

That fix is **insufficient**. The owner went deeper and found the real
cause below.

## Refined (correct) root cause

`[find name=winbox]` was NOT empty — it returned **two** items:

| # | type | comment |
|---|---|---|
| 1 | static  | the persistent `/ip service` row (Winbox listener config) |
| 2 | dynamic | the **current connection** the operator is logged in on |

Visible in `/ip service print` as e.g.:

```
 #   NAME    PORT   ADDRESS         CERTIFICATE      DISABLED
 0   winbox  8291                                    no
15 D c name="winbox" address=10.99.0.1 remote=213.6.169.138:...
```

The `D` flag marks the dynamic current-connection row. When the
operator runs the import **while still connected via WinBox**, both
rows match `name="winbox"`. `/ip service get` against a **multi-item**
ref raises the same `invalid internal item number` error as an empty
ref — and **`:do {} on-error={}` does NOT catch it** in some code
paths (the script halts above the `on-error`).

The length-guard `[:len $ref] > 0` only catches the empty case. It
does not solve multi-match.

## The correct shape

For every `/ip service get` on a name-based lookup:

```rsc
:local winboxSvc ""
:foreach s in=[/ip service find] do={
    :do {
        :if ([/ip service get $s name] = "winbox") do={
            :if ([:tostr [/ip service get $s dynamic]] != "true") do={
                :set winboxSvc $s
            }
        }
    } on-error={}
}
:if ([:len [:tostr $winboxSvc]] > 0) do={
    :local winboxAddr [/ip service get $winboxSvc address]
    # ... use it ...
} else={
    :log warning "hobe-fleet: static winbox service not found; skipping check"
}
```

Properties:

* the outer `foreach` walks **every** `/ip service` row;
* each per-row `get` is wrapped in `:do {} on-error={}` so a malformed
  dynamic row never aborts the loop;
* the inner `dynamic != "true"` predicate **skips the dynamic current-
  connection row** — only the static service row is captured;
* `winboxSvc` ends up either empty (no static row exists — defensive
  fallback that logs + skips) or a **single-item ref**, never a multi-
  item ref.

Apply this shape to **every** `/ip service get` on a name lookup —
not just `winbox`. Currently it's used for `winbox` (§12 check 12) and
`www-ssl` (§5 check 5). Add new instances by extending the same
harness, not by reaching for `[find name=X]` again.

## What's still safe

* `/interface wireguard peers find comment="..."` → length-guard is
  enough; there's no multi-match equivalent for peers.
* `/interface wireguard find name="..."` → length-guard is enough;
  interface names are unique by RouterOS contract.
* `/ip service set <name> ...` → not affected (RouterOS `set` operates
  by name, no internal-ref multi-match issue).

## Tests

`tests/fleet_p3/test_script_service_get_guard.py` pins the contract
at render time:

1. **No `/ip service get [find ...]` survives** in the rendered script.
2. **The foreach-skip-dynamic resolver IS present** (so we can't
   delete the harness and pass).
3. **Every `/ip service get $var` binds to a foreach-safe ref**
   (the iter var `$s` OR a var captured via `:set <var> $s` inside
   the foreach).
4. **Quoted service names** (`find name="winbox"` not `find name=winbox`)
   are still enforced for the documented-stable form.

The wireguard `find`/`get` length-guards remain pinned by sibling
tests (`test_script_hardening.py`, `test_wireguard_provisioning_fixes.py`).

## Related secondary fix — `routeros_api_port` default

While auditing this incident the owner also flagged recurring CHR auth
log noise: `login failure for user hobe-panel via api`. The panel
codebase uses only REST over `https://<wg_mgmt_ip>:8443/rest/` — there
is **no binary RouterOS-API client** in `app/services/routeros_client.py`
or anywhere in the panel. The CHR's `via api` log entry is RouterOS v7
classifying REST auth attempts under the api umbrella.

Root cause of the failed attempts: `fleet/registry/routes_chr.py:225`
defaulted `routeros_api_port` to **8729** (the binary api-ssl port)
when a CHR was created without an explicit port in the POST body.
Rows created with that default kept dialing port 8729 forever. The
metrics collector hit `https://<wg_mgmt_ip>:8729/rest/` against a port
speaking the binary api protocol; the TLS handshake completed but
the HTTP request was treated as a malformed/bad auth attempt,
producing the recurring `via api` log line.

Fix:

* `routes_chr.py:225` — default switched to **8443** (REST/www-ssl) to
  match the column default + the unified script's listener.
* `app/__init__.py` — boot-time self-heal updates any existing row
  with `routeros_api_port=8729` to `8443` (with a log line).

Explicit operator overrides are preserved; only the legacy default is
healed.

## Related secondary fix — `.rsc` route 503 transients

`GET /admin/fleet/onboarding/chr-nodes/<id>/script.rsc` shares its
render pipeline with the JSON `view_node_script` route. The only 503
source is `OnboardingDependencyError`, raised when
`importlib.import_module(sibling)` fails. The owner saw the JSON route
return 200 while the `.rsc` route returned 503 fractions of a second
later — a multi-worker gunicorn pattern where the worker that handled
the second request hadn't yet warmed its `sys.modules` cache.

Fix in `app/__init__.py::_warm_onboarding_lazy_imports`: at boot, eager-
import every sibling Phase-3 module the lazy resolver might touch. After
this fix, **every worker has the modules resident before serving its
first request**.

The existing one-shot retry + text/plain error envelope on the `.rsc`
route remain as defence-in-depth.
