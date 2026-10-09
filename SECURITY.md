# Security notes

## Reporting

Do not post API keys, customer data, or vulnerability details publicly. Before inviting external users, configure a monitored private security contact and an incident-response process.

## Current security controls

- Passwords are stored using salted scrypt digests; sessions use signed, expiring JWTs.
- API keys have high entropy, are stored as SHA-256 hashes, and can be revoked.
- Workspace APIs scope queries to the authenticated workspace or API key's workspace.
- Unknown tools and unregistered/disabled agents are denied by default.
- Approval decisions are bound to a canonical action hash, expire, and cannot be decided twice.
- Execution grants are random opaque tokens stored as hashes, bound to a tenant, agent, tool and exact action hash, expire after 30 seconds, and are consumed atomically once.
- Grant issuance re-checks policy; grant consumption checks current policy. An approved action cannot override an explicit deny policy.
- The included MCP gateway keeps the Guardrail API key in its trusted process and invokes only server-owned sandbox handlers.
- The app adds browser security headers and a basic per-process sign-in failure throttle.
- Production mode disables interactive API documentation endpoints.

## Remaining limitations

This release is not certified and has not been independently penetration-tested. The MCP server handlers in this repository are simulated and do not connect to live business tools. The MCP SDK could not be installed in the build environment because package-index network access was unavailable, so its host/client handshake and end-to-end tool calls were not verified here; see `MCP_INTEGRATION.md`.

The grant is consumed before the downstream tool handler runs. That prevents replay but does not provide atomic exactly-once execution with an external system; a crash between grant consumption and a side effect may require reconciliation. Real connectors need provider-side idempotency, careful retry rules, durable job handling where appropriate, least-privilege credentials, and tests against the actual provider.

Other production gaps include MFA/SSO, account recovery and email verification, distributed rate limiting, formal database migrations, backup/restore drills, operational monitoring and alerting, robust audit retention/redaction, and independent security review. The login throttle is per-process and is not a substitute for a gateway/WAF or distributed rate limiter. Do not connect production payments, sensitive customer data, or destructive tools until these gaps are addressed and independently reviewed.
