"""
SentinelShield — Threat Detector Bridge
Uses real threat detection records from the unified database.
"""
from app.database import SessionLocal, ThreatFindingModel


def detect_threats():
    db = SessionLocal()
    try:
        threats = db.query(ThreatFindingModel).order_by(ThreatFindingModel.id.desc()).limit(20).all()
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
