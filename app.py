from __future__ import annotations

import base64, hashlib, json, os, secrets, time, uuid
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Any, Literal

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, select, desc, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

APP_NAME = "Guardrail"
DATABASE_URL = os.getenv("DATABASE_URL") or ("sqlite:////tmp/guardrail-preview.db" if os.getenv("VERCEL") else "sqlite:///./guardrail.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "720"))
APP_ENV = os.getenv("APP_ENV", "development")
if APP_ENV == "production" and len(JWT_SECRET) < 32:
    raise RuntimeError("Set a strong JWT_SECRET of at least 32 characters in production.")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_urlsafe(48)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
def password_digest(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(derived).decode()

def password_verify(password: str, stored: str) -> bool:
    try:
        algorithm, salt_text, digest_text = stored.split("$", 2)
        if algorithm != "scrypt": return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False
bearer = HTTPBearer(auto_error=False)

class Base(DeclarativeBase): pass

class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(30), default="owner")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(120), default="Default key")
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(20))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("org_id", "id", name="uq_agent_org_external_id"),)
    internal_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    id: Mapped[str] = mapped_column(String(120), index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(500), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    tool: Mapped[str] = mapped_column(String(100), index=True)
    decision: Mapped[str] = mapped_column(String(30))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    max_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    request_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(120))
    action_json: Mapped[str] = mapped_column(Text)
    action_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="PENDING")
    reason: Mapped[str] = mapped_column(String(500), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(36), nullable=True)

class ExecutionGrant(Base):
    """Short-lived, single-use server-to-server permission to execute one exact action."""
    __tablename__ = "execution_grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    request_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(120))
    tool: Mapped[str] = mapped_column(String(100))
    action_hash: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Audit(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    request_id: Mapped[str] = mapped_column(String(36), index=True)
    agent_id: Mapped[str] = mapped_column(String(120), default="")
    tool: Mapped[str] = mapped_column(String(100), default="")
    decision: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(String(500), default="")
    action_hash: Mapped[str] = mapped_column(String(64), default="")
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

Base.metadata.create_all(bind=engine)
_production = APP_ENV.lower() == "production"
app = FastAPI(
    title="Guardrail API",
    version="1.1.0",
    description="AI agent action policy evaluation and approval workflow API.",
    docs_url=None if _production else "/docs",
    redoc_url=None if _production else "/redoc",
    openapi_url=None if _production else "/openapi.json",
)
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Basic per-process login throttling. In a multi-instance production deployment,
# also enforce distributed rate limits at the gateway/WAF (see SECURITY.md).
_LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
_LOGIN_LOCK = Lock()
_LOGIN_WINDOW_SECONDS = 15 * 60
_LOGIN_MAX_ATTEMPTS = 10

def login_rate_limited(key: str) -> bool:
    current = time.monotonic()
    with _LOGIN_LOCK:
        attempts = _LOGIN_ATTEMPTS[key]
        while attempts and current - attempts[0] > _LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        return len(attempts) >= _LOGIN_MAX_ATTEMPTS

def record_login_failure(*keys: str) -> None:
    current = time.monotonic()
    with _LOGIN_LOCK:
        for key in keys:
            attempts = _LOGIN_ATTEMPTS[key]
            while attempts and current - attempts[0] > _LOGIN_WINDOW_SECONDS:
                attempts.popleft()
            attempts.append(current)
        # Bound memory under a stream of unique keys.
        if len(_LOGIN_ATTEMPTS) > 10000:
            stale = [k for k, q in _LOGIN_ATTEMPTS.items() if not q or current - q[-1] > _LOGIN_WINDOW_SECONDS]
            for stale_key in stale[:5000]:
                _LOGIN_ATTEMPTS.pop(stale_key, None)

class RegisterIn(BaseModel):
    organization: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
class PolicyIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    tool: str = Field(min_length=2, max_length=100, pattern=r"^[a-zA-Z][a-zA-Z0-9_.-]*$")
    decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    enabled: bool = True
    max_amount: float | None = Field(default=None, ge=0, le=1_000_000_000)
    description: str = Field(default="", max_length=500)
class AgentIn(BaseModel):
    id: str = Field(min_length=2, max_length=120, pattern=r"^[a-zA-Z0-9_.-]+$")
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=500)
class ActionIn(BaseModel):
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z][a-zA-Z0-9_.-]*$")
    order_id: str | None = Field(default=None, max_length=120)
    customer_id: str | None = Field(default=None, max_length=120)
    amount: float | None = Field(default=None, ge=0, le=1_000_000_000)
    model_config = ConfigDict(extra="forbid")
class EvaluateIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=120)
    action: ActionIn
class KeyIn(BaseModel):
    label: str = Field(default="Default key", min_length=2, max_length=120)
class ApprovalIn(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
class GrantConsumeIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=120)
    action: ActionIn
class ApprovalGrantIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=120)
    action: ActionIn


def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def now(): return datetime.now(timezone.utc)
def hash_action(action: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
def hash_key(key: str) -> str: return hashlib.sha256(key.encode()).hexdigest()
def make_token(user: User) -> str:
    issued = now()
    return jwt.encode({"sub": user.id, "org": user.org_id, "role": user.role, "iat": issued, "exp": issued + timedelta(minutes=JWT_MINUTES)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not creds: raise HTTPException(401, "Sign in required", headers={"WWW-Authenticate":"Bearer"})
    try: payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError: raise HTTPException(401, "Invalid or expired session")
    user = db.get(User, payload.get("sub"))
    if not user or user.org_id != payload.get("org"): raise HTTPException(401, "Invalid session")
    return user

def current_api_org(x_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> str:
    if not x_api_key: raise HTTPException(401, "API key required in X-API-Key header")
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(x_api_key), ApiKey.revoked == False))
    if not key: raise HTTPException(401, "Invalid or revoked API key")
    return key.org_id

def audit(db: Session, org_id: str, request_id: str, agent_id: str, tool: str, decision: str, reason: str, digest: str, action: dict[str, Any]):
    db.add(Audit(org_id=org_id, request_id=request_id, agent_id=agent_id, tool=tool, decision=decision, reason=reason, action_hash=digest, details_json=json.dumps(action, sort_keys=True)))

def policy_decision(db: Session, org_id: str, action: dict[str, Any]) -> tuple[str, str]:
    policies = list(db.scalars(select(Policy).where(Policy.org_id == org_id, Policy.tool == action["tool"], Policy.enabled == True).order_by(Policy.created_at)))
    if not policies: return "DENY", "No enabled policy matches this tool; default deny"
    # An explicit DENY always wins. Approval is required if any matching policy requires it.
    if any(p.decision == "DENY" for p in policies): return "DENY", "Blocked by an enabled deny policy"
    amount = action.get("amount")
    approval_policies = [p for p in policies if p.decision == "REQUIRE_APPROVAL"]
    for p in approval_policies:
        # If a threshold is configured, approval is required only above that threshold.
        if p.max_amount is None or amount is None or amount > p.max_amount:
            return "REQUIRE_APPROVAL", f"Requires human approval under policy '{p.name}'"
    allow_policies = [p for p in policies if p.decision == "ALLOW"]
    if not allow_policies: return "DENY", "No enabled allow policy matches this tool; default deny"
    eligible = [p for p in allow_policies if p.max_amount is None or (amount is not None and amount <= p.max_amount)]
    if not eligible:
        return "DENY", "No enabled allow policy covers this action amount; default deny"
    return "ALLOW", "Matched enabled allow policy"

@app.get("/")
def home(): return FileResponse(str(_STATIC_DIR / "index.html"))

@app.get("/app")
def dashboard(): return FileResponse(str(_STATIC_DIR / "app.html"))
@app.get("/health")
def health(): return {"status":"ok", "service":"guardrail", "environment":APP_ENV}

@app.post("/api/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)): raise HTTPException(409, "An account with this email already exists")
    org = Organization(name=body.organization.strip()); db.add(org); db.flush()
    user = User(org_id=org.id, email=email, password_hash=password_digest(body.password), role="owner"); db.add(user); db.flush()
    # Secure bootstrap policies: no action is permitted until the workspace owner configures one.
    db.commit()
    return {"access_token":make_token(user), "token_type":"bearer", "user":{"id":user.id,"email":user.email,"role":user.role}, "organization":{"id":org.id,"name":org.name}}

@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    client_ip = request.client.host if request.client else "unknown"
    ip_key, email_key = f"ip:{client_ip}", f"email:{email}"
    if login_rate_limited(ip_key) or login_rate_limited(email_key):
        raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.", headers={"Retry-After": str(_LOGIN_WINDOW_SECONDS)})
    user = db.scalar(select(User).where(User.email == email))
    if not user or not password_verify(body.password, user.password_hash):
        record_login_failure(ip_key, email_key)
        raise HTTPException(401, "Email or password is incorrect")
    return {"access_token":make_token(user), "token_type":"bearer", "user":{"id":user.id,"email":user.email,"role":user.role}, "organization":{"id":user.org_id,"name":db.get(Organization,user.org_id).name}}

@app.get("/api/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    org = db.get(Organization, user.org_id)
    return {"id":user.id,"email":user.email,"role":user.role,"organization":{"id":org.id,"name":org.name}}

@app.get("/api/summary")
def summary(user: User = Depends(current_user), db: Session = Depends(get_db)):
    policies = list(db.scalars(select(Policy).where(Policy.org_id == user.org_id)))
    agents = list(db.scalars(select(Agent).where(Agent.org_id == user.org_id)))
    approvals = list(db.scalars(select(Approval).where(Approval.org_id == user.org_id, Approval.status == "PENDING", Approval.expires_at > now())))
    events = list(db.scalars(select(Audit).where(Audit.org_id == user.org_id).order_by(desc(Audit.created_at)).limit(8)))
    return {"policies":len(policies),"enabled_policies":sum(p.enabled for p in policies),"agents":len(agents),"pending_approvals":len(approvals),"events":[audit_out(e) for e in events]}

def policy_out(p: Policy): return {"id":p.id,"name":p.name,"tool":p.tool,"decision":p.decision,"enabled":p.enabled,"max_amount":p.max_amount,"description":p.description,"created_at":p.created_at.isoformat()}
def agent_out(a: Agent): return {"id":a.id,"name":a.name,"description":a.description,"active":a.active,"created_at":a.created_at.isoformat()}
def audit_out(e: Audit): return {"id":e.id,"request_id":e.request_id,"agent_id":e.agent_id,"tool":e.tool,"decision":e.decision,"reason":e.reason,"action_hash":e.action_hash,"created_at":e.created_at.isoformat()}
def approval_out(a: Approval): return {"id":a.id,"request_id":a.request_id,"agent_id":a.agent_id,"action":json.loads(a.action_json),"action_hash":a.action_hash,"status":a.status,"reason":a.reason,"expires_at":a.expires_at.isoformat(),"created_at":a.created_at.isoformat()}

@app.get("/api/policies")
def list_policies(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [policy_out(p) for p in db.scalars(select(Policy).where(Policy.org_id == user.org_id).order_by(Policy.created_at))]
@app.post("/api/policies")
def create_policy(body: PolicyIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = Policy(org_id=user.org_id, **body.model_dump()); db.add(p); db.commit(); db.refresh(p); return policy_out(p)
@app.patch("/api/policies/{policy_id}")
def update_policy(policy_id: str, body: dict[str, Any], user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.scalar(select(Policy).where(Policy.id == policy_id, Policy.org_id == user.org_id))
    if not p: raise HTTPException(404, "Policy not found")
    if set(body) - {"enabled"}: raise HTTPException(422, "Only the enabled flag can be changed here")
    if not isinstance(body.get("enabled"), bool): raise HTTPException(422, "enabled must be a boolean")
    p.enabled = body["enabled"]; db.commit(); return policy_out(p)
@app.delete("/api/policies/{policy_id}")
def delete_policy(policy_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.scalar(select(Policy).where(Policy.id == policy_id, Policy.org_id == user.org_id))
    if not p: raise HTTPException(404, "Policy not found")
    db.delete(p); db.commit(); return {"deleted":True}

@app.get("/api/agents")
def list_agents(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [agent_out(a) for a in db.scalars(select(Agent).where(Agent.org_id == user.org_id).order_by(Agent.created_at))]
@app.post("/api/agents")
def create_agent(body: AgentIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    existing = db.scalar(select(Agent).where(Agent.id == body.id, Agent.org_id == user.org_id))
    if existing: raise HTTPException(409, "Agent ID already exists in this workspace")
    a = Agent(org_id=user.org_id, **body.model_dump()); db.add(a); db.commit(); db.refresh(a); return agent_out(a)
@app.patch("/api/agents/{agent_id}")
def update_agent(agent_id: str, body: dict[str, Any], user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.scalar(select(Agent).where(Agent.id == agent_id, Agent.org_id == user.org_id))
    if not a: raise HTTPException(404, "Agent not found")
    if set(body) - {"active"} or not isinstance(body.get("active"), bool): raise HTTPException(422, "Only active boolean can be changed")
    a.active = body["active"]; db.commit(); return agent_out(a)

@app.post("/api/keys")
def create_key(body: KeyIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    raw = "gr_live_" + secrets.token_urlsafe(32)
    key = ApiKey(org_id=user.org_id, label=body.label, key_hash=hash_key(raw), prefix=raw[:16]); db.add(key); db.commit()
    # Raw key is returned once only; it is never stored in plaintext.
    return {"id":key.id,"label":key.label,"prefix":key.prefix,"api_key":raw,"created_at":key.created_at.isoformat(),"warning":"Copy this key now. It cannot be shown again."}
@app.get("/api/keys")
def list_keys(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [{"id":k.id,"label":k.label,"prefix":k.prefix,"revoked":k.revoked,"created_at":k.created_at.isoformat()} for k in db.scalars(select(ApiKey).where(ApiKey.org_id == user.org_id).order_by(desc(ApiKey.created_at)))]
@app.post("/api/keys/{key_id}/revoke")
def revoke_key(key_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    k = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == user.org_id))
    if not k: raise HTTPException(404, "API key not found")
    k.revoked = True; db.commit(); return {"revoked":True}

@app.post("/v1/evaluate")
def evaluate(body: EvaluateIn, org_id: str = Depends(current_api_org), db: Session = Depends(get_db)):
    agent = db.scalar(select(Agent).where(Agent.id == body.agent_id, Agent.org_id == org_id, Agent.active == True))
    request_id = str(uuid.uuid4()); action = body.action.model_dump(exclude_none=True); digest = hash_action(action)
    if not agent:
        decision, reason = "DENY", "Agent is not registered or is disabled"
    elif action["tool"] in {"read_order", "refund_order"} and not action.get("order_id"):
        decision, reason = "DENY", "order_id is required for this tool"
    elif action["tool"] == "refund_order" and action.get("amount") is None:
        decision, reason = "DENY", "amount is required for refund_order"
    elif action["tool"] == "delete_customer" and not action.get("customer_id"):
        decision, reason = "DENY", "customer_id is required for delete_customer"
    else:
        decision, reason = policy_decision(db, org_id, action)
    if decision == "REQUIRE_APPROVAL":
        approval = Approval(org_id=org_id, request_id=request_id, agent_id=body.agent_id, action_json=json.dumps(action, sort_keys=True), action_hash=digest, reason=reason, expires_at=now()+timedelta(minutes=15))
        db.add(approval)
    audit(db, org_id, request_id, body.agent_id, action["tool"], decision, reason, digest, action)
    db.commit()
    return {"request_id":request_id,"decision":decision,"reason":reason,"action_hash":digest,"approval_expires_in_seconds":900 if decision == "REQUIRE_APPROVAL" else None,"execution":"NOT_EXECUTED","notice":"This API evaluates policy only; it does not execute the requested tool."}

@app.post("/v1/execution-grants/issue")
def issue_execution_grant(body: EvaluateIn, org_id: str = Depends(current_api_org), db: Session = Depends(get_db)):
    """Re-check current policy and issue a short-lived token only for ALLOW decisions."""
    action = body.action.model_dump(exclude_none=True)
    digest = hash_action(action)
    agent = db.scalar(select(Agent).where(Agent.id == body.agent_id, Agent.org_id == org_id, Agent.active == True))
    if not agent:
        raise HTTPException(403, "Agent is not registered or is disabled")
    if action["tool"] in {"read_order", "refund_order"} and not action.get("order_id"):
        raise HTTPException(422, "order_id is required for this tool")
    if action["tool"] == "refund_order" and action.get("amount") is None:
        raise HTTPException(422, "amount is required for refund_order")
    if action["tool"] == "delete_customer" and not action.get("customer_id"):
        raise HTTPException(422, "customer_id is required for delete_customer")
    decision, reason = policy_decision(db, org_id, action)
    request_id = str(uuid.uuid4())
    if decision != "ALLOW":
        audit(db, org_id, request_id, body.agent_id, action["tool"], decision, reason, digest, action)
        db.commit()
        return {"decision": decision, "reason": reason, "request_id": request_id, "execution_grant": None, "execution": "NOT_EXECUTED"}
    raw_token = "grx_" + secrets.token_urlsafe(32)
    db.add(ExecutionGrant(org_id=org_id, request_id=request_id, agent_id=body.agent_id,
                          tool=action["tool"], action_hash=digest, token_hash=hash_key(raw_token),
                          expires_at=now()+timedelta(seconds=30)))
    audit(db, org_id, request_id, body.agent_id, action["tool"], "GRANT_ISSUED",
          "Short-lived execution grant issued after policy re-check", digest, action)
    db.commit()
    return {"decision":"ALLOW", "reason":reason, "request_id":request_id,
            "execution_grant":raw_token, "expires_in_seconds":30, "execution":"NOT_EXECUTED"}

@app.post("/v1/approvals/{request_id}/claim-grant")
def claim_approval_grant(request_id: str, body: ApprovalGrantIn, org_id: str = Depends(current_api_org), db: Session = Depends(get_db)):
    """Claim a single-use grant for the exact action previously approved by a human."""
    action = body.action.model_dump(exclude_none=True)
    digest = hash_action(action)
    approval = db.scalar(select(Approval).where(Approval.request_id == request_id, Approval.org_id == org_id))
    if not approval:
        raise HTTPException(404, "Approval not found")
    if approval.status != "APPROVED":
        raise HTTPException(409, "Approval has not been approved")
    if approval.expires_at.replace(tzinfo=timezone.utc) <= now():
        raise HTTPException(410, "Approval has expired")
    if approval.agent_id != body.agent_id or approval.action_hash != digest or hash_action(json.loads(approval.action_json)) != digest:
        raise HTTPException(409, "Agent or action does not match the approved request")
    existing = db.scalar(select(ExecutionGrant).where(ExecutionGrant.request_id == request_id))
    if existing:
        raise HTTPException(409, "An execution grant was already claimed for this approval")
    current_decision, current_reason = policy_decision(db, org_id, action)
    if current_decision == "DENY":
        raise HTTPException(403, "Current policy denies this action; approval cannot override a deny rule")
    raw_token = "grx_" + secrets.token_urlsafe(32)
    db.add(ExecutionGrant(org_id=org_id, request_id=request_id, agent_id=body.agent_id,
                          tool=action["tool"], action_hash=digest, token_hash=hash_key(raw_token),
                          expires_at=min(approval.expires_at.replace(tzinfo=timezone.utc), now()+timedelta(seconds=30))))
    audit(db, org_id, request_id, body.agent_id, action["tool"], "GRANT_ISSUED",
          "Single-use execution grant claimed for an approved action", digest, action)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(409, "An execution grant was already claimed for this approval")
    return {"execution_grant":raw_token, "expires_in_seconds":30, "execution":"NOT_EXECUTED"}

@app.post("/v1/execution-grants/consume")
def consume_execution_grant(body: GrantConsumeIn, x_execution_grant: str | None = Header(default=None), org_id: str = Depends(current_api_org), db: Session = Depends(get_db)):
    """Atomically consume a token bound to one tenant, agent, tool and exact action."""
    if not x_execution_grant:
        raise HTTPException(401, "Execution grant required")
    action = body.action.model_dump(exclude_none=True)
    digest = hash_action(action)
    grant = db.scalar(select(ExecutionGrant).where(ExecutionGrant.token_hash == hash_key(x_execution_grant), ExecutionGrant.org_id == org_id))
    if not grant:
        raise HTTPException(401, "Invalid execution grant")
    if grant.agent_id != body.agent_id or grant.tool != action["tool"] or grant.action_hash != digest:
        raise HTTPException(403, "Execution grant does not match this agent or exact action")
    if grant.expires_at.replace(tzinfo=timezone.utc) <= now():
        raise HTTPException(410, "Execution grant expired")
    approval = db.scalar(select(Approval).where(Approval.request_id == grant.request_id, Approval.org_id == org_id))
    if approval:
        if approval.status != "APPROVED" or approval.expires_at.replace(tzinfo=timezone.utc) <= now():
            raise HTTPException(403, "Approval is no longer valid")
        current_decision, _ = policy_decision(db, org_id, action)
        if current_decision == "DENY":
            raise HTTPException(403, "Current policy denies this action")
    else:
        current_decision, _ = policy_decision(db, org_id, action)
        if current_decision != "ALLOW":
            raise HTTPException(403, "Current policy no longer allows this action")
    consumed = now()
    result = db.execute(update(ExecutionGrant).where(
        ExecutionGrant.id == grant.id, ExecutionGrant.org_id == org_id,
        ExecutionGrant.consumed_at.is_(None), ExecutionGrant.expires_at > consumed
    ).values(consumed_at=consumed).execution_options(synchronize_session=False))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(409, "Execution grant has already been consumed or expired")
    audit(db, org_id, grant.request_id, body.agent_id, action["tool"], "GRANT_CONSUMED",
          "Single-use execution grant consumed by trusted executor", digest, action)
    db.commit()
    return {"authorized": True, "request_id": grant.request_id, "agent_id": body.agent_id,
            "tool": action["tool"], "action_hash": digest, "execution": "AUTHORIZED_NOT_EXECUTED"}

@app.get("/api/approvals")
def list_approvals(user: User = Depends(current_user), db: Session = Depends(get_db)):
    items = db.scalars(select(Approval).where(Approval.org_id == user.org_id).order_by(desc(Approval.created_at)).limit(200))
    return [approval_out(a) for a in items]
@app.post("/api/approvals/{request_id}/decision")
def decide_approval(request_id: str, body: ApprovalIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.scalar(select(Approval).where(Approval.request_id == request_id, Approval.org_id == user.org_id))
    if not a: raise HTTPException(404, "Approval not found")
    if a.status != "PENDING": raise HTTPException(409, "This request has already been decided")
    if a.expires_at.replace(tzinfo=timezone.utc) < now():
        a.status = "EXPIRED"; db.commit(); raise HTTPException(410, "Approval has expired")
    # Recompute the exact action hash before recording a decision.
    action = json.loads(a.action_json)
    if hash_action(action) != a.action_hash:
        raise HTTPException(409, "Action hash mismatch; approval rejected")
    decided_status = "APPROVED" if body.decision == "APPROVE" else "REJECTED"
    decided_at = now()
    # Compare-and-set makes the decision single-use under concurrent requests.
    result = db.execute(
        update(Approval)
        .where(Approval.id == a.id, Approval.org_id == user.org_id,
               Approval.status == "PENDING", Approval.expires_at > decided_at)
        .values(status=decided_status, decided_at=decided_at, decided_by=user.id)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        fresh = db.scalar(select(Approval).where(Approval.request_id == request_id, Approval.org_id == user.org_id))
        if not fresh:
            raise HTTPException(404, "Approval not found")
        if fresh.status == "PENDING" and fresh.expires_at.replace(tzinfo=timezone.utc) <= now():
            fresh.status = "EXPIRED"
            db.commit()
            raise HTTPException(410, "Approval has expired")
        raise HTTPException(409, "This request has already been decided or expired")
    audit(db, user.org_id, a.request_id, a.agent_id, action["tool"], decided_status,
          "Human decision recorded; no tool was executed", a.action_hash, action)
    db.commit()
    return {"request_id":a.request_id,"status":decided_status,"execution":"NOT_EXECUTED","message":"Decision recorded only. Your execution layer must independently verify and enforce approvals."}

@app.get("/api/audit")
def list_audit(limit: int = 100, user: User = Depends(current_user), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    return [audit_out(e) for e in db.scalars(select(Audit).where(Audit.org_id == user.org_id).order_by(desc(Audit.created_at)).limit(limit))]

@app.post("/api/demo/seed")
def seed_demo(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if db.scalar(select(Policy.id).where(Policy.org_id == user.org_id).limit(1)) is None:
        db.add_all([
            Policy(org_id=user.org_id,name="Order lookup",tool="read_order",decision="ALLOW",description="Permit read-only order lookup"),
            Policy(org_id=user.org_id,name="Small refunds",tool="refund_order",decision="ALLOW",max_amount=1000,description="Allow refunds up to the configured limit"),
            Policy(org_id=user.org_id,name="Refund approval over limit",tool="refund_order",decision="REQUIRE_APPROVAL",max_amount=1000,description="Require human review for refunds above 1000"),
            Policy(org_id=user.org_id,name="Protect customer records",tool="delete_customer",decision="DENY",description="Block customer deletion"),
        ])
    if not db.scalar(select(Agent.id).where(Agent.org_id == user.org_id).limit(1)):
        db.add(Agent(id="support-agent",org_id=user.org_id,name="Support Agent",description="Sample customer-support agent"))
    db.commit(); return {"seeded":True,"message":"Sample policies and agent are ready. Review them before using your own integrations."}

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") or request.url.path.startswith("/v1/") else "no-cache"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if APP_ENV == "production": response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
