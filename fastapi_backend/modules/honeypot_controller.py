"""
SentinelShield — Honeypot Controller Bridge
Connects to HoneypotService.
"""
from app.services.honeypot_service import honeypot_service


def get_honeypots():
    return honeypot_service.list_honeypots()
