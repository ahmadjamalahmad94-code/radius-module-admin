# License Payment Reporting And Reconciliation

The license panel exposes reporting for manual-wallet license payments without
deleting or mutating financial records.

## Reports

- Payments by status, purpose, and provider.
- Current month payment count and amount.
- Pending review count.
- Paid but not applied count.
- Provisioning pending and failed counts.

## Reconciliation Checks

- `paid_without_transaction`: paid requests missing a manual-paid transaction.
- `paid_not_applied`: accepted payments that have not been linked to a license.
- `expired_pending_requests`: pending requests past `expires_at`.
- `duplicate_provider_transaction_risks`: duplicate provider transaction IDs.

## Maintenance

The expiry helper only changes old `pending` requests to `expired`. It never
hard-deletes payment, proof, transaction, provisioning, license, or audit data.
