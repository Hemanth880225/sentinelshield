"""
SentinelShield — Packet Sniffer & Flow Bridge
Fetches real telemetry packets from the database with tenant scoping.
"""
from app.database import SessionLocal, TrafficFlowModel


def capture_packets(tenant_id: str = "default"):
    db = SessionLocal()
    try:
        flows = db.query(TrafficFlowModel).filter_by(
            tenant_id=tenant_id
        ).order_by(TrafficFlowModel.id.desc()).limit(10).all()
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
