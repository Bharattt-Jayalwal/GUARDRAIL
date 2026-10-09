"""Guardrail MCP gateway with trusted, server-side sandbox tool handlers.

Run with: python -m backend.mcp_server
The API key remains in this trusted process and is never exposed as an MCP tool result.
All handlers below are SIMULATED tools. Replace them only with server-side connectors
that cannot be called directly by the model/agent outside this gateway.
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

GUARDRAIL_URL = os.getenv("GUARDRAIL_URL", "http://127.0.0.1:8000").rstrip("/")
GUARDRAIL_API_KEY = os.getenv("GUARDRAIL_API_KEY", "")
GUARDRAIL_AGENT_ID = os.getenv("GUARDRAIL_AGENT_ID", "support-agent")
HTTP_TIMEOUT = float(os.getenv("GUARDRAIL_HTTP_TIMEOUT", "5"))

mcp = FastMCP("Guardrail MCP Gateway")


def _headers() -> dict[str, str]:
    if not GUARDRAIL_API_KEY:
        raise RuntimeError("GUARDRAIL_API_KEY must be configured in the trusted MCP server environment")
    return {"X-API-Key": GUARDRAIL_API_KEY, "Content-Type": "application/json"}


def _post(path: str, payload: dict[str, Any], *, grant: str | None = None) -> dict[str, Any]:
    headers = _headers()
    if grant:
        headers["X-Execution-Grant"] = grant
    try:
        response = httpx.post(f"{GUARDRAIL_URL}{path}", headers=headers, json=payload, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:300]
        raise RuntimeError(f"Guardrail rejected the request ({exc.response.status_code}): {detail}") from exc
    except Exception as exc:
        # Fail closed: never execute a protected tool when Guardrail is unavailable.
        raise PermissionError("Guardrail is unavailable; protected tool was not executed") from exc


def _sandbox_execute(action: dict[str, Any]) -> dict[str, Any]:
    """Only server-owned handlers live here. These are deliberately non-production demos."""
    tool = action["tool"]
    if tool == "read_order":
        order_id = action["order_id"]
        return {"mode": "sandbox", "simulated": True, "order_id": order_id,
                "status": "in_transit", "total": 79.99, "currency": "USD"}
    if tool == "refund_order":
        return {"mode": "sandbox", "simulated": True, "refund_created": False,
                "message": "Demo only: no payment system was contacted.",
                "order_id": action["order_id"], "amount": action["amount"]}
    if tool == "delete_customer":
        return {"mode": "sandbox", "simulated": True, "deleted": False,
                "message": "Demo only: no customer record was deleted.",
                "customer_id": action["customer_id"]}
    raise PermissionError("Tool is not in the server-side execution allowlist")


def _execute_after_grant(action: dict[str, Any], grant: str) -> dict[str, Any]:
    payload = {"agent_id": GUARDRAIL_AGENT_ID, "action": action}
    _post("/v1/execution-grants/consume", payload, grant=grant)
    # Only after the trusted API has atomically consumed the exact-action grant.
    return _sandbox_execute(action)


def _guarded_call(tool: str, **arguments: Any) -> dict[str, Any]:
    action = {"tool": tool, **{k: v for k, v in arguments.items() if v is not None}}
    evaluated = _post("/v1/evaluate", {"agent_id": GUARDRAIL_AGENT_ID, "action": action})
    decision = evaluated.get("decision")
    if decision == "DENY":
        return {"status": "blocked", "decision": decision, "reason": evaluated.get("reason"),
                "request_id": evaluated.get("request_id"), "executed": False}
    if decision == "REQUIRE_APPROVAL":
        return {"status": "pending_approval", "decision": decision,
                "reason": evaluated.get("reason"), "request_id": evaluated.get("request_id"),
                "expires_in_seconds": evaluated.get("approval_expires_in_seconds", 900),
                "executed": False,
                "next_step": "A workspace approver must approve this request in Guardrail. Then call execute_approved with this request_id and the exact same action arguments."}
    if decision != "ALLOW":
        raise PermissionError("Guardrail returned an unknown decision; action was not executed")
    # Re-evaluate current policy when issuing the grant to avoid trusting stale decisions.
    issued = _post("/v1/execution-grants/issue", {"agent_id": GUARDRAIL_AGENT_ID, "action": action})
    if issued.get("decision") != "ALLOW" or not issued.get("execution_grant"):
        return {"status": "blocked", "decision": issued.get("decision", "DENY"),
                "reason": issued.get("reason", "Could not issue execution grant"), "executed": False}
    result = _execute_after_grant(action, issued["execution_grant"])
    return {"status": "executed_in_sandbox", "decision": "ALLOW", "request_id": issued["request_id"],
            "executed": True, "result": result}


@mcp.tool()
def read_order(order_id: str) -> dict[str, Any]:
    """Look up a synthetic order through Guardrail policy enforcement. No live system is accessed."""
    return _guarded_call("read_order", order_id=order_id)


@mcp.tool()
def refund_order(order_id: str, amount: float) -> dict[str, Any]:
    """Request a refund in the sandbox. Sensitive amounts may require human approval; no money moves."""
    if amount < 0:
        raise ValueError("amount must be non-negative")
    return _guarded_call("refund_order", order_id=order_id, amount=amount)


@mcp.tool()
def delete_customer(customer_id: str) -> dict[str, Any]:
    """Attempt a sandbox customer deletion; default policies should deny this action."""
    return _guarded_call("delete_customer", customer_id=customer_id)


@mcp.tool()
def execute_approved(request_id: str, tool: str, order_id: str | None = None,
                     customer_id: str | None = None, amount: float | None = None) -> dict[str, Any]:
    """Execute the exact action a human approved, using a one-time server-side grant.

    The request ID and all action arguments must match the original pending request.
    This tool only calls the built-in sandbox handlers in this project.
    """
    if tool not in {"read_order", "refund_order", "delete_customer"}:
        raise ValueError("Tool is not in the server-side execution allowlist")
    action = {"tool": tool}
    if order_id is not None: action["order_id"] = order_id
    if customer_id is not None: action["customer_id"] = customer_id
    if amount is not None: action["amount"] = amount
    claim = _post(f"/v1/approvals/{request_id}/claim-grant",
                  {"agent_id": GUARDRAIL_AGENT_ID, "action": action})
    result = _execute_after_grant(action, claim["execution_grant"])
    return {"status": "executed_in_sandbox", "decision": "APPROVED", "request_id": request_id,
            "executed": True, "result": result}


if __name__ == "__main__":
    # MCP stdio transport: do not print logs to stdout; stdout is the protocol channel.
    mcp.run(transport="stdio")
