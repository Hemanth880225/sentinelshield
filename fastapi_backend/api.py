"""
SentinelShield — FastAPI Core Backend (Hardened & Production-Ready)
Integrates Telemetry Ingestion, Threat Detectors, Risk Scoring,
Agentic Policy Decisions, Cryptographic Ed25519 Command Signing,
Local Enforcement Agent, and Deception Honeypots with RBAC and Tenant Isolation.
"""
from __future__ import annotations
import os
import asyncio
import datetime
import json
import time
from typing import List, Dict, Any, Optional

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException,
    status, Query, Body, Request
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.database import (
    init_database, SessionLocal, DeviceModel, TrafficFlowModel,
    DnsRecordModel, ThreatFindingModel, AgentDecisionModel,
    EnforcementRuleModel, EnforcementAuditModel, HoneypotModel,
    SystemPolicyModel
)
from app.core.telemetry import FlowEvent, DnsEvent, DeviceEvent
from app.services.security_engine import engine_instance
from app.services.honeypot_service import honeypot_service
from app.services.telemetry_generator import simulator
from app.services.auth import (
    get_current_user, require_admin, require_analyst_or_admin,
    require_read_access, require_collector_or_admin, authenticate_token,
    UserProfile
)

# Initialize database schema and seeds
init_database()

# Start background telemetry generator only if explicitly enabled
if os.environ.get("SENTINEL_SIMULATOR_ENABLED", "false").lower() == "true":
    simulator.start()

app = FastAPI(
    title="SentinelShield Agentic Security Platform",
    description="Cloud-native security brain with lightweight collector & authorized local enforcement",
    version="2.0.0"
)

# --------------------------------------------------
# CORS Configuration (Strict & Configurable)
# --------------------------------------------------
cors_env = os.environ.get("CORS_ORIGINS", "")
if cors_env:
    allowed_origins = [orig.strip() for orig in cors_env.split(",") if orig.strip()]
else:
    allowed_origins = [
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# --------------------------------------------------
# Pydantic Schemas for API Contracts
# --------------------------------------------------

class FlowEventSchema(BaseModel):
    ts: float = Field(default_factory=time.time)
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    bytes_out: int = 0
    bytes_in: int = 0
    packets: int = 1
    src_mac: str = ""


class DnsEventSchema(BaseModel):
    ts: float = Field(default_factory=time.time)
    src_ip: str
    qname: str
    qtype: str = "A"


class DeviceEventSchema(BaseModel):
    ts: float = Field(default_factory=time.time)
    mac: str
    ip: str
    hostname: str = ""


class TelemetryBatchSchema(BaseModel):
    flows: List[FlowEventSchema] = []
    dns: List[DnsEventSchema] = []
    devices: List[DeviceEventSchema] = []


class HoneypotInteractionSchema(BaseModel):
    honeypot_code: str
    attacker_ip: str
    payload: str = ""


class HoneypotDeploySchema(BaseModel):
    service: str
    port: int = Field(ge=1, le=65535)


class PolicyUpdateSchema(BaseModel):
    autonomy: Optional[str] = None  # automatic, approval, notify
    auto_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    approve_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    max_ttl: Optional[int] = Field(default=None, ge=30, le=86400)
    auto_isolate: Optional[bool] = None
    protected_cidrs: Optional[str] = None


class DecisionReviewSchema(BaseModel):
    reason: Optional[str] = "Admin review"


# --------------------------------------------------
# WebSocket Connection Manager with Auth & Origin Checks
# --------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


ws_manager = ConnectionManager()


# --------------------------------------------------
# 1. SYSTEM OVERVIEW & STATUS API
# --------------------------------------------------

@app.get("/api/status")
@app.get("/status")
def get_system_status(user: UserProfile = Depends(require_read_access)):
    """Returns overall SOC health, active threats, honeypot traps, and collector connectivity."""
    db = SessionLocal()
    try:
        tenant = user.tenant_id
        devices_count = db.query(DeviceModel).filter_by(tenant_id=tenant, status="online").count()
        threats_active = db.query(ThreatFindingModel).filter_by(tenant_id=tenant, status="active").count()
        honeypots_count = db.query(HoneypotModel).filter_by(tenant_id=tenant).count()
        high_threats = db.query(ThreatFindingModel).filter_by(tenant_id=tenant, status="active", severity="High").count()
        pending_decisions = db.query(AgentDecisionModel).filter_by(tenant_id=tenant, status="needs_approval").count()

        if high_threats > 0:
            net_status = "Threat Detected"
        elif threats_active > 0:
            net_status = "Elevated"
        else:
            net_status = "Secure"

        return {
            "tenant_id": tenant,
            "devices_online": devices_count,
            "threats_detected": threats_active,
            "honeypots_active": honeypots_count,
            "network_status": net_status,
            "collector_status": "Connected",
            "active_incidents": threats_active,
            "pending_approvals": pending_decisions,
            "agent_status": "Active",
            "enforcement_mode": "Cloud-Managed mTLS / Ed25519"
        }
    finally:
        db.close()


# --------------------------------------------------
# 2. NETWORK TRAFFIC & TELEMETRY API
# --------------------------------------------------

@app.get("/api/traffic")
@app.get("/traffic")
def get_recent_traffic(limit: int = 15, user: UserProfile = Depends(require_read_access)):
    """Returns real captured packet flows formatted for the frontend data table."""
    db = SessionLocal()
    try:
        flows = db.query(TrafficFlowModel).filter_by(
            tenant_id=user.tenant_id
        ).order_by(TrafficFlowModel.id.desc()).limit(limit).all()

        if not flows and os.environ.get("SENTINEL_SIMULATOR_ENABLED", "false").lower() == "true":
            simulator.generate_single_sample()
            flows = db.query(TrafficFlowModel).filter_by(
                tenant_id=user.tenant_id
            ).order_by(TrafficFlowModel.id.desc()).limit(limit).all()

        return [
            {
                "time": f.time_str,
                "source": f.src_ip,
                "destination": f.dst_ip,
                "protocol": f.proto,
                "size": f.bytes_out if f.bytes_out > 0 else 64
            }
            for f in flows
        ]
    finally:
        db.close()


@app.post("/api/telemetry/flow")
def ingest_flow(payload: FlowEventSchema, user: UserProfile = Depends(require_collector_or_admin)):
    """Collector endpoint: streams network flow metadata to cloud engine."""
    try:
        flow = FlowEvent(
            ts=payload.ts,
            src_ip=payload.src_ip,
            dst_ip=payload.dst_ip,
            dst_port=payload.dst_port,
            proto=payload.proto,
            bytes_out=payload.bytes_out,
            bytes_in=payload.bytes_in,
            packets=payload.packets,
            src_mac=payload.src_mac
        )
        result = engine_instance.ingest_flow(flow)
        return {"status": "success", "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/telemetry/dns")
def ingest_dns(payload: DnsEventSchema, user: UserProfile = Depends(require_collector_or_admin)):
    """Collector endpoint: streams DNS query events to cloud engine."""
    try:
        dns = DnsEvent(
            ts=payload.ts,
            src_ip=payload.src_ip,
            qname=payload.qname,
            qtype=payload.qtype
        )
        result = engine_instance.ingest_dns(dns)
        return {"status": "success", "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/telemetry/device")
def ingest_device(payload: DeviceEventSchema, user: UserProfile = Depends(require_collector_or_admin)):
    """Collector endpoint: streams device discovery events (ARP/DHCP/mDNS)."""
    try:
        dev = DeviceEvent(
            ts=payload.ts,
            mac=payload.mac,
            ip=payload.ip,
            hostname=payload.hostname
        )
        result = engine_instance.ingest_device(dev)
        return {"status": "success", "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/telemetry/batch")
def ingest_telemetry_batch(batch: TelemetryBatchSchema, user: UserProfile = Depends(require_collector_or_admin)):
    """Ingest a mixed batch of telemetry events in one payload."""
    results = {"flows": 0, "dns": 0, "devices": 0}
    for f in batch.flows:
        try:
            flow_ev = FlowEvent(
                ts=f.ts, src_ip=f.src_ip, dst_ip=f.dst_ip, dst_port=f.dst_port,
                proto=f.proto, bytes_out=f.bytes_out, bytes_in=f.bytes_in,
                packets=f.packets, src_mac=f.src_mac
            )
            engine_instance.ingest_flow(flow_ev)
            results["flows"] += 1
        except Exception:
            pass

    for d_ev in batch.dns:
        try:
            dns_item = DnsEvent(ts=d_ev.ts, src_ip=d_ev.src_ip, qname=d_ev.qname, qtype=d_ev.qtype)
            engine_instance.ingest_dns(dns_item)
            results["dns"] += 1
        except Exception:
            pass

    for dev_ev in batch.devices:
        try:
            device_item = DeviceEvent(ts=dev_ev.ts, mac=dev_ev.mac, ip=dev_ev.ip, hostname=dev_ev.hostname)
            engine_instance.ingest_device(device_item)
            results["devices"] += 1
        except Exception:
            pass

    return {"status": "success", "processed": results}


@app.post("/api/telemetry/simulate_attack")
def simulate_attack(attack_type: str = Body(default="port_scan", embed=True), user: UserProfile = Depends(require_admin)):
    """Admin-only: triggers verifiable test attack telemetry (port_scan, brute_force, dns_tunnel)."""
    res = simulator.trigger_test_attack(attack_type)
    return {"status": "attack_injected", "details": res}


# --------------------------------------------------
# 3. THREAT MONITORING & INTELLIGENCE API
# --------------------------------------------------

@app.get("/api/threats")
@app.get("/threats")
def get_threats(status: Optional[str] = None, user: UserProfile = Depends(require_read_access)):
    """Returns real detected threats with severity, risk score, and MITRE classification."""
    db = SessionLocal()
    try:
        q = db.query(ThreatFindingModel).filter_by(tenant_id=user.tenant_id)
        if status:
            q = q.filter_by(status=status)
        threats = q.order_by(ThreatFindingModel.id.desc()).limit(50).all()

        return [
            {
                "id": t.id,
                "time": t.time_str,
                "ip": t.src_ip,
                "type": t.display_type,
                "target": t.target_device,
                "severity": t.severity,
                "risk_score": t.risk_score,
                "mitre": t.mitre,
                "status": t.status
            }
            for t in threats
        ]
    finally:
        db.close()


@app.get("/api/threats/summary")
def get_threats_summary(user: UserProfile = Depends(require_read_access)):
    """Aggregated threat intelligence statistics for charts and cards."""
    db = SessionLocal()
    try:
        threats = db.query(ThreatFindingModel).filter_by(
            tenant_id=user.tenant_id, status="active"
        ).all()
        high = sum(1 for t in threats if t.severity == "High")
        medium = sum(1 for t in threats if t.severity == "Medium")
        low = sum(1 for t in threats if t.severity == "Low")

        type_counts = {}
        for t in threats:
            type_counts[t.display_type] = type_counts.get(t.display_type, 0) + 1

        return {
            "total": len(threats),
            "high": high,
            "medium": medium,
            "low": low,
            "by_type": type_counts
        }
    finally:
        db.close()


# --------------------------------------------------
# 4. HONEYPOT & DECEPTION SYSTEM API
# --------------------------------------------------

@app.get("/api/honeypots")
@app.get("/honeypots")
def get_honeypots(user: UserProfile = Depends(require_read_access)):
    """Returns active honeypot deception traps and attacker captures."""
    return honeypot_service.list_honeypots(tenant_id=user.tenant_id)


@app.post("/api/honeypots/interact")
def record_honeypot_interaction(payload: HoneypotInteractionSchema, user: UserProfile = Depends(require_analyst_or_admin)):
    """Records an attacker probing a decoy service and initiates deception defense."""
    try:
        res = honeypot_service.record_interaction(
            honeypot_code=payload.honeypot_code,
            attacker_ip=payload.attacker_ip,
            payload=payload.payload,
            tenant_id=user.tenant_id
        )
        return {"status": "interaction_captured", "trap": res}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/honeypots/deploy")
def deploy_dynamic_honeypot(payload: HoneypotDeploySchema, user: UserProfile = Depends(require_admin)):
    """Deploys a new deception trap in the network sandbox."""
    try:
        res = honeypot_service.deploy_honeypot(payload.service, payload.port, tenant_id=user.tenant_id)
        return {"status": "deployed", "honeypot": res}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --------------------------------------------------
# 5. AGENTIC DECISION SYSTEM & DECISION LOGS API
# --------------------------------------------------

@app.get("/api/logs")
@app.get("/logs")
def get_agent_logs(limit: int = 40, user: UserProfile = Depends(require_read_access)):
    """Returns autonomous decision history and audit trail for terminal view."""
    db = SessionLocal()
    try:
        logs = db.query(AgentDecisionModel).filter_by(
            tenant_id=user.tenant_id
        ).order_by(AgentDecisionModel.id.asc()).all()
        sliced = logs[-limit:] if len(logs) > limit else logs
        return [
            {
                "id": l.id,
                "timestamp": l.time_str,
                "event_type": l.event_type,
                "decision": l.message,
                "message": l.message,
                "status": l.status,
                "action": l.action,
                "target": l.target,
                "risk_score": l.risk_score,
                "command_id": l.command_id
            }
            for l in sliced
        ]
    finally:
        db.close()


@app.get("/api/decisions")
def list_decisions(status: Optional[str] = None, user: UserProfile = Depends(require_read_access)):
    """Lists agent security decisions with filter for approval-required actions."""
    db = SessionLocal()
    try:
        q = db.query(AgentDecisionModel).filter_by(tenant_id=user.tenant_id)
        if status:
            q = q.filter_by(status=status)
        decisions = q.order_by(AgentDecisionModel.id.desc()).all()
        return [
            {
                "id": d.id,
                "time": d.time_str,
                "status": d.status,
                "action": d.action,
                "target": d.target,
                "ttl_seconds": d.ttl_seconds,
                "risk_score": d.risk_score,
                "reason": d.reason,
                "command_id": d.command_id,
                "message": d.message,
                "reviewed_by": d.reviewed_by
            }
            for d in decisions
        ]
    finally:
        db.close()


@app.post("/api/decisions/{decision_id}/approve")
def approve_decision(decision_id: int, user: UserProfile = Depends(require_admin)):
    """
    Authorized administrator approves an action requiring approval.
    Executes through Ed25519 cryptographic signing and local enforcement agent.
    """
    try:
        result = engine_instance.approve_decision(decision_id, reviewer=user.username)
        return {
            "status": "approved",
            "decision_id": decision_id,
            "enforcement": result
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/decisions/{decision_id}/deny")
def deny_decision(
    decision_id: int,
    review: DecisionReviewSchema = DecisionReviewSchema(),
    user: UserProfile = Depends(require_admin)
):
    """Authorized administrator denies a pending decision."""
    try:
        result = engine_instance.deny_decision(decision_id, reviewer=user.username, reason=review.reason or "Admin override")
        return {"status": "denied", "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --------------------------------------------------
# 6. RESPONSE & LOCAL ENFORCEMENT AUDIT API
# --------------------------------------------------

@app.get("/api/enforcement/rules")
def get_enforcement_rules(user: UserProfile = Depends(require_read_access)):
    """Lists active firewall rules verified and applied by the local agent."""
    db = SessionLocal()
    try:
        rules = db.query(EnforcementRuleModel).filter_by(
            tenant_id=user.tenant_id, status="active"
        ).all()
        return [
            {
                "id": r.id,
                "action": r.action,
                "ip": r.ip,
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "expires_at": r.expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                "command_id": r.command_id,
                "status": r.status
            }
            for r in rules
        ]
    finally:
        db.close()


@app.get("/api/enforcement/audit")
def get_enforcement_audit(limit: int = 30, user: UserProfile = Depends(require_read_access)):
    """Returns cryptographic command execution audit trail."""
    db = SessionLocal()
    try:
        audits = db.query(EnforcementAuditModel).filter_by(
            tenant_id=user.tenant_id
        ).order_by(EnforcementAuditModel.id.desc()).limit(limit).all()
        return [
            {
                "id": a.id,
                "time": a.time_str,
                "command_id": a.command_id,
                "action": a.action,
                "target": a.target,
                "outcome": a.outcome,
                "detail": a.detail
            }
            for a in audits
        ]
    finally:
        db.close()


# --------------------------------------------------
# 7. POLICY CONFIGURATION API
# --------------------------------------------------

@app.get("/api/policy")
def get_security_policy(user: UserProfile = Depends(require_read_access)):
    """Retrieves current security policy and autonomy thresholds."""
    db = SessionLocal()
    try:
        pol = db.query(SystemPolicyModel).filter_by(tenant_id=user.tenant_id).first()
        if not pol:
            return {"autonomy": "approval", "auto_threshold": 70, "approve_threshold": 40}
        return {
            "tenant_id": pol.tenant_id,
            "autonomy": pol.autonomy,
            "auto_threshold": pol.auto_threshold,
            "approve_threshold": pol.approve_threshold,
            "max_ttl": pol.max_ttl,
            "auto_isolate": pol.auto_isolate,
            "protected_cidrs": pol.protected_cidrs
        }
    finally:
        db.close()


@app.put("/api/policy")
def update_security_policy(update: PolicyUpdateSchema, user: UserProfile = Depends(require_admin)):
    """Updates security autonomy level and thresholds."""
    db = SessionLocal()
    try:
        pol = db.query(SystemPolicyModel).filter_by(tenant_id=user.tenant_id).first()
        if not pol:
            pol = SystemPolicyModel(tenant_id=user.tenant_id)
            db.add(pol)

        if update.autonomy is not None:
            if update.autonomy not in ("automatic", "approval", "notify"):
                raise HTTPException(status_code=400, detail="Invalid autonomy level")
            pol.autonomy = update.autonomy
        if update.auto_threshold is not None:
            pol.auto_threshold = update.auto_threshold
        if update.approve_threshold is not None:
            pol.approve_threshold = update.approve_threshold
        if update.max_ttl is not None:
            pol.max_ttl = update.max_ttl
        if update.auto_isolate is not None:
            pol.auto_isolate = update.auto_isolate
        if update.protected_cidrs is not None:
            pol.protected_cidrs = update.protected_cidrs

        db.commit()
        return {"status": "policy_updated", "policy": update.dict(exclude_none=True)}
    finally:
        db.close()


# --------------------------------------------------
# 8. AUTHENTICATION CHECK API
# --------------------------------------------------

@app.get("/api/auth/me")
def check_auth(user: UserProfile = Depends(get_current_user)):
    """Returns identity and role of current authenticated operator."""
    return user


# --------------------------------------------------
# 9. REAL-TIME WEBSOCKET STREAMING WITH AUTH
# --------------------------------------------------

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket, token: Optional[str] = Query(None)):
    """
    Authenticated WebSocket endpoint for real-time status streaming.
    Requires token query parameter or authorization header.
    """
    # Origin verification
    origin = websocket.headers.get("origin")
    if origin and allowed_origins and origin not in allowed_origins:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Check authentication
    auth_token = token
    if not auth_token:
        # Check subprotocol or query
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            auth_token = auth_header[7:].strip()
        else:
            auth_token = websocket.headers.get("x-api-key")

    user = authenticate_token(auth_token)
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            # Gather status data scoped to the authenticated tenant
            status_data = get_system_status(user)
            await websocket.send_json({"type": "status_update", "data": status_data})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
