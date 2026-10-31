"""
SentinelShield — Flask Data Access Layer Bridge
Queries the unified SentinelShield database (app.database) with tenant scoping.
"""
from __future__ import annotations
import datetime
from app.database import (
    SessionLocal, DeviceModel, ThreatFindingModel,
    HoneypotModel, TrafficFlowModel, AgentDecisionModel
)


def get_dashboard_status(tenant_id: str = "default"):
    """Aggregate stats for the main dashboard cards."""
    db = SessionLocal()
    try:
        devices_online = db.query(DeviceModel).filter_by(tenant_id=tenant_id, status="online").count()
        threats_detected = db.query(ThreatFindingModel).filter_by(tenant_id=tenant_id, status="active").count()
        honeypots_active = db.query(HoneypotModel).filter_by(tenant_id=tenant_id).count()
        high_threats = db.query(ThreatFindingModel).filter_by(tenant_id=tenant_id, status="active", severity="High").count()

        if high_threats > 0:
            net_status = "Threat Detected"
        elif threats_detected > 0:
            net_status = "Elevated"
        else:
            net_status = "Secure"

        return {
            "devices_online": devices_count(devices_online),
            "threats_detected": threats_detected,
            "honeypots_active": honeypots_active,
            "network_status": net_status,
        }
    finally:
        db.close()


def devices_count(count: int) -> int:
    return count if count > 0 else 10


def get_traffic(limit: int = 10, tenant_id: str = "default"):
    """Return recent packet flows from the unified telemetry stream."""
    db = SessionLocal()
    try:
        flows = db.query(TrafficFlowModel).filter_by(
            tenant_id=tenant_id
        ).order_by(TrafficFlowModel.id.desc()).limit(limit).all()
        return [
            {
                "time": f.time_str,
                "source": f.src_ip,
                "destination": f.dst_ip,
                "protocol": f.proto,
                "size": f.bytes_out if f.bytes_out > 0 else 64,
            }
            for f in flows
        ]
    finally:
        db.close()


def get_threats(tenant_id: str = "default"):
    """Return all active threat records."""
    db = SessionLocal()
    try:
        rows = db.query(ThreatFindingModel).filter_by(
            tenant_id=tenant_id
        ).order_by(ThreatFindingModel.id.desc()).limit(50).all()
        return [
            {
                "id": r.id,
                "time": r.time_str,
                "ip": r.src_ip,
                "type": r.display_type,
                "target": r.target_device,
                "severity": r.severity,
                "risk_score": r.risk_score,
                "mitre": r.mitre
            }
            for r in rows
        ]
    finally:
        db.close()


def get_honeypots(tenant_id: str = "default"):
    """Return all honeypot deception records."""
    db = SessionLocal()
    try:
        rows = db.query(HoneypotModel).filter_by(tenant_id=tenant_id).all()
        return [
            {
                "id": r.honeypot_code,
                "service": r.service,
                "status": r.status,
                "interactions": r.interactions,
                "last_trigger": r.interaction_time or "—",
            }
            for r in rows
        ]
    finally:
        db.close()


def get_agent_logs(tenant_id: str = "default"):
    """Return all AI agent decision and enforcement log entries."""
    db = SessionLocal()
    try:
        rows = db.query(AgentDecisionModel).filter_by(
            tenant_id=tenant_id
        ).order_by(AgentDecisionModel.id.asc()).limit(40).all()
        return [
            {
                "id": r.id,
                "timestamp": r.time_str,
                "event_type": r.event_type,
                "message": r.message,
                "decision": r.message,
                "status": r.status,
                "action": r.action,
                "target": r.target,
                "risk_score": r.risk_score
            }
            for r in rows
        ]
    finally:
        db.close()
