# Project Scope

This project is the central vendor/admin licensing panel for selling and managing RADIUS subscriptions.

It is not the customer RADIUS application, and it is not the customer-facing RADIUS dashboard.

It must remain standalone and must not import code, modules, models, services, or assets from:

- `C:\Users\Ahmad J Ahmad\Desktop\hub\radius-module`
- `C:\Users\Ahmad J Ahmad\Desktop\hub\radius-module-app`

This panel controls licenses and subscriptions only:

- Customers
- Subscription plans
- License keys
- License status
- Expiration and grace periods
- Server fingerprints
- Manual renewals
- License check logs
- Audit logs

Customer RADIUS installations will call:

```text
POST /api/license/check
```

The customer installation is responsible for enforcing limited or denied mode locally based on the API response.
