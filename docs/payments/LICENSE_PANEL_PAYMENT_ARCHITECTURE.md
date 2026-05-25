# License Panel Payment Architecture

This document belongs to `radius-module-admin` only. It covers commercial
payments for selling HobeRadius licenses, subscriptions, setup fees, renewals,
upgrades, and capacity increases. Customer-network payments for cards,
subscribers, distributors, loans, or topups belong to `radius-module`.

## Source Of Truth

The Flask license panel is the source of truth for payment state, provisioning
orders, license activation, renewals, and capacity entitlement changes. Client
portals may display instructions and submit proof, but they must not decide that
a payment is paid or that a license should be activated.

## Payment Modes

- `manual_wallet`: first supported mode. The wallet number is payment routing
  information only. Admin review is required before a payment is accepted.
- `jawwal_pay_gateway_future`: reserved for a future official signed provider
  integration. It must remain disabled until official API documentation,
  credentials, webhook signature rules, and idempotency identifiers are known.

## Flow

1. Customer or admin creates a license payment request.
2. Customer receives manual wallet instructions and a reference code.
3. Customer submits proof or a future provider sends a signed webhook.
4. Admin or verified provider flow marks the request `paid`.
5. A provisioning order moves from payment waiting to provisioning work.
6. License changes are applied only by an idempotent backend operation.
7. Delivery is tracked separately from payment because some installations need
   VPS setup, testing, or manual handoff.

## Payment Purposes

- `new_subscription`
- `renewal`
- `upgrade`
- `capacity_increase`
- `setup_fee`

## Provisioning Statuses

- `payment_pending`
- `paid`
- `provisioning_pending`
- `provisioning_in_progress`
- `testing`
- `ready`
- `delivered`
- `failed`
- `needs_manual_review`

`paid` does not always mean instant license delivery. Some customers require
VPS provisioning or operational preparation within a 24 hour window before the
license can be marked ready or delivered.

## Relation To Licenses And Plans

Payment requests can reference a customer, plan, existing license, or target
capacity entitlement. Approved payments do not directly mutate licenses unless
the license-apply workflow runs and records that it has applied exactly once.
The public license check API must remain compatible with existing active,
grace, limited, and denied states.

## Security Rules

- Wallet number is not proof of payment.
- Manual approval is required unless a future signed provider webhook passes.
- Provider events must be idempotent.
- Duplicate payment approval must not duplicate license activation or renewal.
- Financial records should be append-only; corrections use reversal or
  correction records, not hard deletes.
- Secrets, VPS credentials, and provider credentials must not be shown in
  customer-visible payment screens.
