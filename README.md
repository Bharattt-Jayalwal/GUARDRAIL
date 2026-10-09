# Guardrail SaaS MVP

Guardrail is a deployable early-stage SaaS application for AI-agent policy evaluation. It includes a web dashboard, tenant-scoped workspaces, password-based authentication, persistent SQL storage, hashed API keys, registered agents, configurable policy rules, approval tracking, audit events, a Python SDK, Docker deployment, and tests.

**Product status: hardened pilot candidate, not a certified or production-hardened security product.** The service evaluates actions and records decisions. It does not execute business tools, and approval decisions are not execution grants. Before handling live customer data, refunds, or account changes, implement a trusted execution gateway that cannot be bypassed, perform an independent security review, and test against the actual agent/tool architecture.

## Features

- Workspace registration and sign-in; scrypt password hashing and signed, expiring JWT sessions.
- Workspace-scoped policies, agents, API keys, approvals, and audit events.
- API keys are shown once and stored as SHA-256 hashes; keys can be revoked.
- Default-deny policy evaluation for unregistered/disabled agents and unknown tools.
- Deny rules take priority; approval policies can use an amount threshold.
- Human approval decisions are bound to a canonical action hash, expire after 15 minutes, and cannot be decided twice.
- MCP gateway source with an explicit server-side sandbox tool allowlist.
- Short-lived, action-bound execution grants that are stored as hashes, re-check policy, expire quickly, and are atomically single-use.
- Approval-to-grant flow that checks the exact approved action and rejects replay.
- SQLAlchemy storage: SQLite for local development, PostgreSQL for hosted deployment.
- CSV audit export, responsive dashboard, REST API docs at `/docs`, and a Python SDK.
- Browser security headers, production-mode API-docs disablement, a basic per-process sign-in failure throttle, and automated tests.


## Public website and workspace

The project now includes a responsive public marketing website at `/` and the authenticated Guardrail dashboard at `/app`. The homepage includes product sections, a browser-only policy simulator, a developer API snippet, early-access information, and an FAQ. The original workspace interface is preserved in `static/app.html`; the site assets are in `static/`. A vector favicon is available at `/static/favicon.svg`, and `static/brand-logo.png` contains the generated brand artwork.

Before publishing, replace the placeholder `hello@guardrail.example` email address in `static/index.html` with a monitored inbox and review the wording/pricing for your actual offer. The demo numbers and policies shown on the homepage are illustrative only.

## Run locally

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt
# Set a stable local secret (PowerShell): $env:JWT_SECRET="a-long-random-local-secret-value"
# macOS/Linux: export JWT_SECRET="a-long-random-local-secret-value"
uvicorn backend.app:app --reload
```

Open `http://127.0.0.1:8000`. Interactive API docs are at `http://127.0.0.1:8000/docs`.

SQLite is created as `guardrail.db` in the working directory. For local testing, `APP_ENV` defaults to `development`; for production the app refuses to start without a `JWT_SECRET` of at least 32 characters.

## Quick start in the app

1. Create a workspace with a unique email and a password of at least 12 characters.
2. Click **Load sample setup** to add a support agent and sample policies.
3. Open **API keys**, create a key, and copy it immediately. It cannot be retrieved again.
4. Open **Test console**, paste the API key, and test `read_order`, `refund_order`, or `delete_customer`.
5. Open **Approvals** to review a `REQUIRE_APPROVAL` request. Approval records a decision only; no real action runs.

Sample policy semantics: order lookups are allowed, refund amounts up to 1000 are allowed, refunds above 1000 require human approval, and customer deletion is denied. Adjust these rules for your own sandbox.

## Docker

```bash
docker build -t guardrail .
docker run --rm -p 8000:8000 \
  -e APP_ENV=production \
  -e JWT_SECRET="replace-with-a-strong-random-secret-at-least-32-characters" \
  -e DATABASE_URL="sqlite:////app/guardrail.db" \
  -v guardrail-data:/app \
  guardrail
```

For a real deployment, prefer managed PostgreSQL and persistent storage. Do not commit `.env`, database files, or API keys.

## Deploy to Render

1. Upload this project to a **private GitHub repository**.
2. In Render, choose **New + → Blueprint** and connect the repository; Render reads `render.yaml`.
3. Review the web service and managed PostgreSQL database, then deploy. The blueprint generates `JWT_SECRET`.
4. Confirm `/health` returns `{"status":"ok", ...}` and sign up to create a workspace.
5. Set up custom domain and HTTPS, backups, monitoring, alerting, and a privacy/retention policy before inviting pilot users.

The included Render blueprint uses paid starter/basic plans; confirm current pricing in Render before deploying. You can instead use another Docker-capable host and managed PostgreSQL.

## API overview

- `POST /api/auth/register` — create workspace and owner.
- `POST /api/auth/login` — create a session.
- `/api/policies`, `/api/agents`, `/api/approvals`, `/api/audit`, `/api/keys` — dashboard APIs, protected by a bearer token.
- `POST /v1/evaluate` — policy evaluation, protected by `X-API-Key`.
- `POST /v1/execution-grants/issue` — re-check policy and issue a short-lived grant for ALLOW actions.
- `POST /v1/execution-grants/consume` — atomically consume an exact-action grant inside a trusted executor.
- `POST /v1/approvals/{request_id}/claim-grant` — claim a one-time grant for the exact approved action.
- `GET /health` — health check.
- `GET /docs` — OpenAPI docs.

Example evaluation:

```bash
curl -X POST "$GUARDRAIL_URL/v1/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $GUARDRAIL_API_KEY" \
  -d '{"agent_id":"support-agent","action":{"tool":"read_order","order_id":"order_123"}}'
```

## SDK

```python
from guardrail_sdk import GuardrailClient

client = GuardrailClient()  # uses GUARDRAIL_URL and GUARDRAIL_API_KEY
result = client.evaluate("support-agent", {"tool": "read_order", "order_id": "order_123"})
if result["decision"] != "ALLOW":
    raise PermissionError(result["reason"])
# A trusted server-side executor must perform the actual tool call only after this check.
```

To import the SDK, add `backend/` to your application's package path or copy/package it into your internal SDK distribution. Never allow an untrusted model to decide whether to honor the result.

## MCP integration

See [`MCP_INTEGRATION.md`](MCP_INTEGRATION.md) for the Guardrail MCP gateway, local setup, MCP client configuration, and approval-flow testing. The MCP server uses a separate optional dependency file (`backend/requirements-mcp.txt`) so the API service does not need the MCP SDK installed. The bundled MCP handlers are sandbox-only and do not access live business systems.

The execution-grant API is intended for a trusted server-side executor. Keep the Guardrail API key and grant token out of model-visible outputs. A policy decision alone is not permission to execute: the gateway must consume the one-time grant before invoking its server-owned handler.

## Tests

```bash
pip install -r backend/requirements.txt
cd backend
pytest -q
```

## Important gaps before commercial production

This is a practical pilot foundation, not a final security guarantee. The repository now includes a one-time, short-lived, action-bound grant API and a sandbox MCP gateway. Before live customer use:

1. Wire every protected tool path through the trusted gateway and remove direct credentials/routes that let agents bypass it.
2. Replace only the sandbox handlers with carefully scoped server-side connectors; implement provider idempotency and recovery for uncertain outcomes.
3. Add database migrations, backups/restore drills, transaction/replay controls, distributed rate limits, abuse monitoring, structured redaction, and operational alerts.
4. Add MFA/SSO, password reset, email verification, account lockout, role management, audit retention controls, and a privacy/data-processing agreement as appropriate.
5. Review tenant isolation, secret management, dependency/container vulnerabilities, and threat model with an independent security engineer; run integration and penetration tests.
6. Validate every policy against business requirements and edge cases. Do not send secrets, payment data, or unnecessary personal data in action payloads.
7. Confirm applicable privacy/security obligations with qualified counsel before selling into regulated environments.

Do not claim Guardrail makes AI agents “fully safe” or “unhackable.” Describe it accurately as a policy evaluation and approval workflow layer until execution enforcement is complete and independently tested.
