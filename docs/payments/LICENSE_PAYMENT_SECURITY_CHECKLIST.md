# License Payment Security Checklist

- Manual wallet numbers are payment routing instructions only.
- Proof submission never marks a request paid.
- Admin approval is required before `paid`.
- License apply is a separate idempotent operation after `paid`.
- Duplicate apply attempts reuse stored `applied_result_json`.
- Payment records are not hard-deleted.
- Reconciliation endpoints do not expose provider secrets, license signing
  secrets, admin sessions, private notes, or raw stack traces.
- Jawwal Pay automation remains out of scope until official signed webhook
  verification is implemented.
