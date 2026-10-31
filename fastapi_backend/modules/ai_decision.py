"""
SentinelShield — AI Decision Log Bridge
Fetches real agent decision and enforcement logs.
"""
from app.database import SessionLocal, AgentDecisionModel


def get_agent_logs():
    db = SessionLocal()
    try:
        logs = db.query(AgentDecisionModel).order_by(AgentDecisionModel.id.asc()).limit(30).all()
        return [l.message for l in logs]
    finally:
        db.close()
