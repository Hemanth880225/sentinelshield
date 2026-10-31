"""
SentinelShield — Honeypot Controller Bridge
Connects to HoneypotService with tenant scoping.
"""
from app.services.honeypot_service import honeypot_service


def get_honeypots(tenant_id: str = "default"):
    return honeypot_service.list_honeypots(tenant_id=tenant_id)
