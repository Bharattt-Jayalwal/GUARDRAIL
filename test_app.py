import os
os.environ["DATABASE_URL"] = "sqlite:///./guardrail_test.db"
os.environ["JWT_SECRET"] = "test-secret-key-long-enough-for-automated-tests-only"
os.environ["APP_ENV"] = "testing"

from fastapi.testclient import TestClient
from backend.app import app, SessionLocal, Base, engine

client = TestClient(app)

def register():
    import uuid
    email = f"test-{uuid.uuid4().hex[:10]}@example.com"
    r = client.post("/api/auth/register", json={"organization":"Test Workspace", "email":email, "password":"very-secure-test-password"})
    assert r.status_code == 200, r.text
    return r.json(), email

def auth(token): return {"Authorization":f"Bearer {token}"}

def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"

def test_signup_login_and_tenant_scope():
    data, email = register()
    assert data["access_token"]
    login = client.post("/api/auth/login", json={"email":email,"password":"very-secure-test-password"})
    assert login.status_code == 200
    assert client.get("/api/me",headers=auth(data["access_token"])).status_code == 200

def test_unknown_tool_defaults_to_deny():
    data,_ = register(); h=auth(data["access_token"])
    client.post("/api/agents",headers=h,json={"id":"test-agent","name":"Test Agent"})
    key=client.post("/api/keys",headers=h,json={"label":"test key"}).json()["api_key"]
    r=client.post("/v1/evaluate",headers={"X-API-Key":key},json={"agent_id":"test-agent","action":{"tool":"unlisted_tool"}})
    assert r.status_code==200 and r.json()["decision"]=="DENY"

def test_allow_policy_and_agent_registration():
    data,_=register(); h=auth(data["access_token"])
    client.post("/api/agents",headers=h,json={"id":"support-agent","name":"Support Agent"})
    client.post("/api/policies",headers=h,json={"name":"Read orders","tool":"read_order","decision":"ALLOW"})
    key=client.post("/api/keys",headers=h,json={"label":"test key"}).json()["api_key"]
    r=client.post("/v1/evaluate",headers={"X-API-Key":key},json={"agent_id":"support-agent","action":{"tool":"read_order","order_id":"123"}})
    assert r.status_code==200 and r.json()["decision"]=="ALLOW"
    assert r.json()["execution"]=="NOT_EXECUTED"

def test_approval_is_recorded_but_not_executed():
    data,_=register(); h=auth(data["access_token"])
    client.post("/api/agents",headers=h,json={"id":"support-agent","name":"Support Agent"})
    client.post("/api/policies",headers=h,json={"name":"Refund review","tool":"refund_order","decision":"REQUIRE_APPROVAL"})
    key=client.post("/api/keys",headers=h,json={"label":"test key"}).json()["api_key"]
    r=client.post("/v1/evaluate",headers={"X-API-Key":key},json={"agent_id":"support-agent","action":{"tool":"refund_order","order_id":"123","amount":20}})
    assert r.status_code==200 and r.json()["decision"]=="REQUIRE_APPROVAL"
    request_id=r.json()["request_id"]
    decided=client.post(f"/api/approvals/{request_id}/decision",headers=h,json={"decision":"APPROVE"})
    assert decided.status_code==200
    assert decided.json()["status"]=="APPROVED"
    assert decided.json()["execution"]=="NOT_EXECUTED"

def test_api_key_revocation():
    data,_=register(); h=auth(data["access_token"])
    k=client.post("/api/keys",headers=h,json={"label":"revoke me"}).json()
    client.post(f"/api/keys/{k['id']}/revoke",headers=h)
    r=client.post("/v1/evaluate",headers={"X-API-Key":k["api_key"]},json={"agent_id":"anything","action":{"tool":"read_order"}})
    assert r.status_code==401

def test_workspace_data_isolation():
    first,_=register(); second,_=register()
    h1=auth(first["access_token"]); h2=auth(second["access_token"])
    client.post("/api/policies",headers=h1,json={"name":"Private policy","tool":"read_order","decision":"ALLOW"})
    assert len(client.get("/api/policies",headers=h1).json()) == 1
    assert client.get("/api/policies",headers=h2).json() == []

def test_refund_threshold_requires_approval():
    data,_=register(); h=auth(data["access_token"])
    client.post("/api/agents",headers=h,json={"id":"refund-agent","name":"Refund Agent"})
    client.post("/api/policies",headers=h,json={"name":"Refunds under 1000","tool":"refund_order","decision":"ALLOW","max_amount":1000})
    client.post("/api/policies",headers=h,json={"name":"Review over 1000","tool":"refund_order","decision":"REQUIRE_APPROVAL","max_amount":1000})
    key=client.post("/api/keys",headers=h,json={"label":"threshold key"}).json()["api_key"]
    low=client.post("/v1/evaluate",headers={"X-API-Key":key},json={"agent_id":"refund-agent","action":{"tool":"refund_order","order_id":"123","amount":500}}).json()
    high=client.post("/v1/evaluate",headers={"X-API-Key":key},json={"agent_id":"refund-agent","action":{"tool":"refund_order","order_id":"123","amount":1500}}).json()
    assert low["decision"] == "ALLOW"
    assert high["decision"] == "REQUIRE_APPROVAL"

def test_approval_cannot_be_decided_twice():
    data, _ = register(); h = auth(data["access_token"])
    client.post("/api/agents", headers=h, json={"id":"approval-agent","name":"Approval Agent"})
    client.post("/api/policies", headers=h, json={"name":"Review refunds","tool":"refund_order","decision":"REQUIRE_APPROVAL"})
    key = client.post("/api/keys", headers=h, json={"label":"approval key"}).json()["api_key"]
    evaluated = client.post("/v1/evaluate", headers={"X-API-Key":key}, json={"agent_id":"approval-agent","action":{"tool":"refund_order","order_id":"order-1","amount":25}}).json()
    endpoint = f"/api/approvals/{evaluated['request_id']}/decision"
    first = client.post(endpoint, headers=h, json={"decision":"APPROVE"})
    second = client.post(endpoint, headers=h, json={"decision":"REJECT"})
    assert first.status_code == 200
    assert second.status_code == 409

def test_security_headers_are_present():
    response = client.get("/health")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert "default-src 'self'" in response.headers.get("content-security-policy", "")

def test_execution_grant_is_action_bound_and_single_use():
    data, _ = register(); h = auth(data["access_token"])
    client.post("/api/agents", headers=h, json={"id":"grant-agent", "name":"Grant Agent"})
    client.post("/api/policies", headers=h, json={"name":"Allow order read", "tool":"read_order", "decision":"ALLOW"})
    key = client.post("/api/keys", headers=h, json={"label":"grant key"}).json()["api_key"]
    api = {"X-API-Key": key}
    action = {"tool":"read_order", "order_id":"order-1"}
    issued = client.post("/v1/execution-grants/issue", headers=api, json={"agent_id":"grant-agent", "action":action})
    assert issued.status_code == 200 and issued.json()["execution_grant"]
    token = issued.json()["execution_grant"]
    wrong = client.post("/v1/execution-grants/consume", headers={**api, "X-Execution-Grant":token},
                        json={"agent_id":"grant-agent", "action":{"tool":"read_order", "order_id":"order-2"}})
    assert wrong.status_code == 403
    consumed = client.post("/v1/execution-grants/consume", headers={**api, "X-Execution-Grant":token},
                           json={"agent_id":"grant-agent", "action":action})
    assert consumed.status_code == 200 and consumed.json()["authorized"] is True
    replay = client.post("/v1/execution-grants/consume", headers={**api, "X-Execution-Grant":token},
                         json={"agent_id":"grant-agent", "action":action})
    assert replay.status_code == 409

def test_approved_action_gets_one_time_grant_bound_to_exact_action():
    data, _ = register(); h = auth(data["access_token"])
    client.post("/api/agents", headers=h, json={"id":"approved-agent", "name":"Approved Agent"})
    client.post("/api/policies", headers=h, json={"name":"Review refunds", "tool":"refund_order", "decision":"REQUIRE_APPROVAL"})
    key = client.post("/api/keys", headers=h, json={"label":"approved grant key"}).json()["api_key"]
    api = {"X-API-Key":key}
    action = {"tool":"refund_order", "order_id":"order-9", "amount":25}
    evaluated = client.post("/v1/evaluate", headers=api, json={"agent_id":"approved-agent", "action":action}).json()
    request_id = evaluated["request_id"]
    decision = client.post(f"/api/approvals/{request_id}/decision", headers=h, json={"decision":"APPROVE"})
    assert decision.status_code == 200
    claim = client.post(f"/v1/approvals/{request_id}/claim-grant", headers=api,
                        json={"agent_id":"approved-agent", "action":action})
    assert claim.status_code == 200
    token = claim.json()["execution_grant"]
    altered = client.post("/v1/execution-grants/consume", headers={**api, "X-Execution-Grant":token},
                          json={"agent_id":"approved-agent", "action":{"tool":"refund_order", "order_id":"order-9", "amount":250}})
    assert altered.status_code == 403
    consumed = client.post("/v1/execution-grants/consume", headers={**api, "X-Execution-Grant":token},
                           json={"agent_id":"approved-agent", "action":action})
    assert consumed.status_code == 200
    claim_again = client.post(f"/v1/approvals/{request_id}/claim-grant", headers=api,
                              json={"agent_id":"approved-agent", "action":action})
    assert claim_again.status_code == 409

def test_denied_action_cannot_get_execution_grant():
    data, _ = register(); h = auth(data["access_token"])
    client.post("/api/agents", headers=h, json={"id":"deny-agent", "name":"Deny Agent"})
    client.post("/api/policies", headers=h, json={"name":"Deny deletion", "tool":"delete_customer", "decision":"DENY"})
    key = client.post("/api/keys", headers=h, json={"label":"deny key"}).json()["api_key"]
    response = client.post("/v1/execution-grants/issue", headers={"X-API-Key":key},
                           json={"agent_id":"deny-agent", "action":{"tool":"delete_customer", "customer_id":"c-1"}})
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"
    assert response.json()["execution_grant"] is None
