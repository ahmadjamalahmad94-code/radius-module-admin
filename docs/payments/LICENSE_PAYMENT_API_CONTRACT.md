# License Payment API Contract

This contract belongs to `radius-module-admin` and covers HobeRadius license
panel payments only. It does not apply to customer-network collections inside
`radius-module`.

## Manual Wallet Request APIs

Admin JSON endpoints are session-protected and return JSON only:

- `GET /admin/api/payments/settings`
- `PATCH /admin/api/payments/settings`
- `POST /admin/api/payments/requests`
- `GET /admin/api/payments/requests`
- `GET /admin/api/payments/requests/<id>`

Portal-safe endpoints are scoped to a single payment request token:

- `POST /api/license-payments/requests`
- `GET /api/license-payments/requests/<id>/instructions?token=<token>`

## Safety Rules

- A wallet number is routing information only.
- New requests start as `pending`.
- Client payloads cannot set `status=paid`.
- Proof submission is text-only in the first implementation: reference number
  and note. File uploads require a separate safe upload review.
- Proof submission changes `pending` to `proof_submitted`; it never marks the
  payment paid.
- Payment instructions expose amount, currency, receiver wallet, wallet owner,
  reference code, expiry, and status only.
- Provider secrets, license signing secrets, admin sessions, and raw stack
  traces are never returned.
- Service provisioning and license activation remain separate workflows.
