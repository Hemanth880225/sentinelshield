"""
SentinelShield — AI Decision Log Bridge
Fetches real agent decision and enforcement logs with tenant scoping.
"""
from app.database import SessionLocal, AgentDecisionModel


def get_agent_logs(tenant_id: str = "default"):
    db = SessionLocal()
    try:
        logs = db.query(AgentDecisionModel).filter_by(
            tenant_id=tenant_id
        ).order_by(AgentDecisionModel.id.asc()).limit(30).all()
        return [l.message for l in logs]
    finally:
        db.close()
