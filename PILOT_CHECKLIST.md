# Guardrail pilot checklist

## Before a customer demo
- [ ] Use a private source repository and keep all secrets out of Git.
- [ ] Deploy with HTTPS and a managed PostgreSQL database.
- [ ] Set a strong JWT secret, verify backups, and configure gateway/WAF rate limits.
- [ ] Confirm production mode is enabled and interactive API docs are disabled.
- [ ] Create a separate workspace and API key for each pilot.
- [ ] Use synthetic customer/order data only.
- [ ] Review sample policies with the customer; policy names and thresholds are examples.
- [ ] Demonstrate ALLOW, DENY, REQUIRE_APPROVAL, disabled-agent, unknown-tool, expired-approval, and revoked-key cases.
- [ ] Run the API test suite and test the MCP handshake in the actual target MCP client; the SDK handshake was not verified in the build environment.
- [ ] Demonstrate that an allowed MCP call consumes a one-time grant, and that altered/replayed grants fail.
- [ ] Explain that included MCP handlers are sandbox simulations and do not execute real business actions.

## Before any live integration
- [ ] Put the enforcement check inside a trusted execution gateway that all protected tool calls must pass through.
- [ ] Ensure AI agents cannot access tool credentials or direct endpoints that bypass the gateway.
- [ ] Replace sandbox handlers with narrowly scoped server-side connectors; do not give credentials to the model.
- [ ] Implement provider idempotency, durable execution status, and safe recovery/reconciliation for uncertain outcomes.
- [ ] Test grant expiry, replay, modified payloads, concurrent claims, policy changes, revoked keys, provider errors, and cross-tenant access.
- [ ] Add rate limits, alerting, data minimization/redaction, retention controls, backup/restore testing, and incident response.
- [ ] Add MFA/SSO and account recovery appropriate to the customer.
- [ ] Have an independent security engineer review and test the deployment.
- [ ] Obtain customer approval for a sandbox pilot and agree on data handling terms.
