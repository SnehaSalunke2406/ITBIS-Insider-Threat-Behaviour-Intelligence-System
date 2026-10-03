# ITBIS Security & UI Upgrade

Implemented in this build:

- Security response headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
- Restricted CORS to the local application origins used by this Windows build.
- Login attempt throttling: 8 attempts per 5 minutes per client IP.
- JWT authentication remains required for protected API endpoints.
- Audit logging remains enabled for security-sensitive analysis and update actions.
- Frontend adds secure-session indicators, live console status, and an alert badge.
- UI refreshed as a dedicated SOC/security operations console with responsive styling.

For a public deployment, HTTPS and a production-grade identity provider/session store should be used; this build is intended for the local internship/demo environment.
