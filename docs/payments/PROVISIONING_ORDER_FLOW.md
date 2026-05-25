# Provisioning Order Flow

Provisioning orders track the work needed after a HobeRadius license payment.
They are separate from payment records because a paid order can still require
VPS preparation, license generation, testing, or manual delivery.

## Status Model

- `payment_pending`: order is waiting for a payment request to be paid.
- `paid`: payment is accepted, but provisioning has not been scheduled yet.
- `provisioning_pending`: ready for an operator or automation to start.
- `provisioning_in_progress`: setup work is underway.
- `testing`: service, license, or customer environment is being checked.
- `ready`: work is complete and ready for customer delivery.
- `delivered`: customer has received the license or setup handoff.
- `failed`: provisioning could not complete and needs remediation.
- `needs_manual_review`: the order cannot safely continue without admin review.

## Normal Manual Wallet Path

1. Create payment request for `new_subscription`, `renewal`, `upgrade`,
   `capacity_increase`, or `setup_fee`.
2. Create or link a provisioning order with `payment_pending`.
3. Customer follows wallet instructions and submits proof.
4. Admin reviews the proof.
5. Approval marks the payment `paid` and moves the order to `paid` or
   `provisioning_pending`.
6. Operator progresses the order through setup, testing, ready, and delivered.

## Delivery Timing

The portal must not promise instant delivery for orders that require VPS or
manual setup. The safe customer message is that payment was received and the
subscription will be prepared within 24 hours when the order requires
provisioning.

## License Apply Guard

License activation, renewal, upgrade, or capacity changes must be idempotent.
The apply workflow should store which payment or provisioning order was applied
so repeated approvals, retries, or duplicate provider events cannot extend or
activate the license twice.

## Secret Handling

Provisioning notes can be internal. Customer-visible delivery data must not
include raw VPS passwords, provider credentials, private keys, or other secrets
unless the project has a dedicated secure secret delivery mechanism.
