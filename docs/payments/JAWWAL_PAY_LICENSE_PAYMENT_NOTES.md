# Jawwal Pay License Payment Notes

Jawwal Pay support in the license panel is future work. The project must not
pretend to know official gateway fields, webhook signatures, success statuses,
or idempotency identifiers before official documentation and credentials are
available.

## Current Position

- Manual Wallet ships first.
- Wallet number is payment routing only.
- Manual admin approval is required to mark a license payment paid.
- Jawwal Pay must be disabled by default.

## Requirements Before API Mode

- Official Jawwal Pay merchant API documentation.
- Sandbox and production credentials with environment separation.
- Webhook signature verification rules.
- Stable provider event ID or transaction ID for idempotency.
- Clear mapping from provider event to one local license payment request.
- Runbook for delayed, duplicated, failed, reversed, or disputed payments.

## Safe Shell Behavior

Until real provider details exist:

- Creating a Jawwal Pay payment should return `provider_not_configured` or
  equivalent disabled response.
- Unsigned webhook payloads may be stored for diagnostics only.
- Unknown webhook fields must not be interpreted as paid.
- Webhooks must not activate, renew, upgrade, or extend any license.
- Provider secrets must never appear in logs, responses, or customer-visible UI.

## Future Paid Flow

1. Provider creates or accepts a payment intent.
2. Provider sends a signed webhook or backend verifies status through official
   API.
3. Backend verifies signature and idempotency.
4. Backend maps the event to exactly one local payment request.
5. Backend marks the request paid only for confirmed success events.
6. Provisioning and license application run through existing idempotent backend
   workflows.
