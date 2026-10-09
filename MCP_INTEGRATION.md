# Guardrail MCP Gateway (sandbox integration)

This release includes a Model Context Protocol (MCP) server at `backend/mcp_server.py`. It exposes a small, explicit allowlist of tools and routes them through Guardrail's policy API before a server-owned handler can run.

**Important scope:** the bundled tool handlers are synthetic demonstrations. They do not connect to Shopify, payment processors, customer databases, or other live systems. Do not describe this integration as protecting an existing MCP server unless all sensitive tool calls are routed through this gateway and direct bypass paths/credentials are removed.

## Architecture

1. The MCP client/model sees the tools exposed by this gateway, not the API key.
2. The gateway sends the requested action to `POST /v1/evaluate`.
3. `DENY` returns without executing a handler. `REQUIRE_APPROVAL` creates a pending request and returns without execution.
4. For `ALLOW`, the gateway asks the API to re-check the current policy and issue a random, 30-second execution grant.
5. The trusted gateway submits the exact action and grant to `POST /v1/execution-grants/consume`. The API checks tenant, agent, tool, canonical action hash, expiry, current policy, and single-use state. Only after successful consumption does the gateway call its local sandbox handler.
6. For approved requests, `execute_approved` claims a single-use grant only if the request is approved, unexpired, and the agent/action exactly match. The grant is then consumed before the sandbox handler runs.

Grant tokens are random, stored as hashes in the API database, short-lived, action-bound, and single-use. They are intended only for trusted server-to-server use. Never expose the Guardrail API key or grant token to an untrusted model or browser.

## Run locally

1. Install the API dependencies and start the API as described in `README.md`.
2. In the dashboard, create a workspace, register an agent whose ID is `support-agent` (or change `GUARDRAIL_AGENT_ID`), create policies, and create an API key. Copy the API key once.
3. In a separate terminal, from the repository root:

```bash
python -m pip install -r backend/requirements-mcp.txt
# Linux/macOS shell; use the equivalent environment-variable syntax on Windows PowerShell.
export GUARDRAIL_URL="http://127.0.0.1:8000"
export GUARDRAIL_API_KEY="gr_live_REPLACE_WITH_YOUR_KEY"
export GUARDRAIL_AGENT_ID="support-agent"
python -m backend.mcp_server
```

The MCP server uses stdio. It intentionally does not start a public network listener. Configure your MCP-compatible client to launch it as a subprocess.

## Example MCP client configuration

Use the equivalent MCP server configuration for your client. Keep this configuration on a trusted machine and do not share it publicly because it contains a secret.

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "python",
      "args": ["-m", "backend.mcp_server"],
      "cwd": "/ABSOLUTE/PATH/TO/guardrail-saas",
      "env": {
        "GUARDRAIL_URL": "https://YOUR-GUARDRAIL-HOST",
        "GUARDRAIL_API_KEY": "gr_live_REPLACE_WITH_YOUR_KEY",
        "GUARDRAIL_AGENT_ID": "support-agent"
      }
    }
  }
}
```

Replace the path, URL, and API key. Use HTTPS when the API is hosted remotely. For production deployments, use the client's supported secret/environment manager rather than hard-coding a key in a shared config.

## Test the approval flow

1. Configure `read_order` as `ALLOW`.
2. Configure `refund_order` as `REQUIRE_APPROVAL` or use a threshold policy that requires approval.
3. Call `read_order` in your MCP client. The result should be a simulated sandbox order.
4. Call `refund_order`. It should return a pending approval request ID and must not run the handler.
5. Sign into the Guardrail dashboard as the workspace owner and approve that request.
6. Call `execute_approved` with the request ID and the *exact same* tool and arguments. It should run only the sandbox handler.
7. Try to reuse the same approval or change the amount/order ID. The API should reject replay or mismatched actions.
8. Confirm `delete_customer` is denied by the sample policy.

## Extending to a real connector

Do not simply replace the sandbox return values with live API calls. Before a live connector is enabled:

- Keep the actual connector credentials only in the trusted gateway process/secret manager; the model must not have direct access.
- Make every path to the protected resource go through the gateway. Remove direct agent credentials and bypassable routes.
- Use provider-side idempotency keys and reconcile uncertain outcomes. The grant is consumed before the external side effect; if a process crashes between consumption and the call, the action may need operator reconciliation.
- Enforce least-privilege scopes, resource ownership/tenant checks, argument schemas, limits, and explicit tool allowlists inside the handler.
- Use a durable job/outbox pattern for long-running actions, with execution status and retry rules; do not blindly retry money-moving operations.
- Test concurrent calls, token replay, approval expiry, revoked API keys, policy changes, provider errors, and cross-tenant access.
- Have an independent security engineer review the integration and threat model before live customer data or financial actions are enabled.

## What is implemented vs. not verified

Implemented in this repository:

- MCP stdio server source exposing four guarded tools (`read_order`, `refund_order`, `delete_customer`, `execute_approved`).
- Server-side allowlist and sandbox-only tool handlers.
- API-issued short-lived grants for allow decisions; grant hashes persisted in the database.
- Approval-bound grant claim and atomic single-use consumption, exact-action hash checks, expiry checks, current-policy checks, tenant and agent binding.
- Automated API tests for grant issuance, action mismatch, replay, approval claims, and denial.

Verified in this environment:

- The FastAPI test suite passes (13 tests).
- Python syntax compilation can be checked for the MCP server source.

Not verified here:

- Installing/running the official MCP SDK, because package-index network access was unavailable in this environment.
- A real MCP host/client handshake or end-to-end MCP tool call.
- Any live external connector, penetration test, compliance certification, high availability, or production security assurance.
