"""Minimal Guardrail client. This evaluates policy; it does not execute tools."""
from __future__ import annotations
import os
import httpx
from typing import Any

class GuardrailClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: float = 5.0):
        self.base_url = (base_url or os.environ.get("GUARDRAIL_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("GUARDRAIL_API_KEY", "")
        self.timeout = timeout
        if not self.base_url or not self.api_key:
            raise ValueError("Set GUARDRAIL_URL and GUARDRAIL_API_KEY")

    def evaluate(self, agent_id: str, action: dict[str, Any]) -> dict[str, Any]:
        try:
            response = httpx.post(
                f"{self.base_url}/v1/evaluate",
                headers={"X-API-Key": self.api_key},
                json={"agent_id": agent_id, "action": action},
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json()
            if result.get("decision") not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}:
                raise RuntimeError("Guardrail returned an unknown decision")
            return result
        except Exception as exc:
            # Fail closed: callers must not run a protected tool when Guardrail is unavailable.
            raise PermissionError("Guardrail policy check failed; protected action must not run") from exc

    def require_allow(self, agent_id: str, action: dict[str, Any]) -> dict[str, Any]:
        result = self.evaluate(agent_id, action)
        if result["decision"] != "ALLOW":
            raise PermissionError(result.get("reason", "Action not allowed by Guardrail"))
        return result
