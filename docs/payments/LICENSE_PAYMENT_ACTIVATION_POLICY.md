# License Payment Activation Policy

Approved manual-wallet payments become eligible for license changes only after
admin review marks the request `paid`.

## Purpose Mapping

- `renewal`: extends the linked license once and writes a renewal record.
- `upgrade`: changes the linked license to the paid target plan once.
- `new_subscription`: creates an active license only when the linked
  provisioning order is `ready` or `delivered`.
- `capacity_increase`: records a manual follow-up result until a capacity
  override workflow exists.
- `setup_fee`: records the paid setup fee and does not mutate a license.

## Idempotency

Each `license_payment_request` stores `applied_at`, `applied_action`, and an
`applied_result_json` payload. Once set, repeat apply attempts return the stored
result without creating duplicate renewals, upgrades, or licenses.
