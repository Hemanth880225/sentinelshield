"""
SentinelShield — Threat Detector Bridge
Uses real threat detection records from the unified database with tenant scoping.
"""
from app.database import SessionLocal, ThreatFindingModel


def detect_threats(tenant_id: str = "default"):
    db = SessionLocal()
    try:
        threats = db.query(ThreatFindingModel).filter_by(
            tenant_id=tenant_id
        ).order_by(ThreatFindingModel.id.desc()).limit(20).all()
        return [
            {
                "time": t.time_str,
                "ip": t.src_ip,
                "type": t.display_type,
                "target": t.target_device,
                "severity": t.severity
            }
            for t in threats
        ]
    finally:
        db.close()
