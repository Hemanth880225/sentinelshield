"""
SentinelShield — Packet Sniffer & Flow Bridge
Fetches real telemetry packets from the database.
"""
from app.database import SessionLocal, TrafficFlowModel


def capture_packets():
    db = SessionLocal()
    try:
        flows = db.query(TrafficFlowModel).order_by(TrafficFlowModel.id.desc()).limit(10).all()
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
