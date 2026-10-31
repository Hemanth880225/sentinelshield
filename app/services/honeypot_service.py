"""
SentinelShield — Honeypot & Deception Service
Manages dynamic deception traps, simulates/records attacker interactions,
and feeds deception telemetry into the core security engine.
"""
from __future__ import annotations
import time
import datetime
import random
from typing import Optional, List, Dict

from app.database import SessionLocal, HoneypotModel, AgentDecisionModel
from app.core.telemetry import FlowEvent
from app.services.security_engine import engine_instance


class HoneypotService:
    def list_honeypots(self) -> List[Dict]:
        db = SessionLocal()
        try:
            traps = db.query(HoneypotModel).all()
            return [
                {
                    "id": h.honeypot_code,
                    "service": h.service,
                    "port": h.port,
                    "status": h.status,
                    "attacker_ip": h.attacker_ip or "None",
                    "interactions": h.interactions,
                    "last_trigger": h.interaction_time or "—"
                }
                for h in traps
            ]
        finally:
            db.close()

    def deploy_honeypot(self, service: str, port: int) -> Dict:
        db = SessionLocal()
        try:
            count = db.query(HoneypotModel).count()
            code = f"HP-{count + 1}"
            new_trap = HoneypotModel(
                honeypot_code=code,
                service=service,
                port=port,
                status="Active",
                interactions=0
            )
            db.add(new_trap)

            # Log deployment in agent logs
            now_str = datetime.datetime.now().strftime("%H:%M:%S")
            log = AgentDecisionModel(
                time_str=now_str,
                event_type="deployment",
                status="auto_approved",
                action="deploy_honeypot",
                target=f"0.0.0.0:{port}",
                risk_score=0,
                reason="Dynamic deception trap provisioned",
                message=f"Deploying {service} deception trap on port {port} ({code})"
            )
            db.add(log)
            db.commit()
            return {"id": code, "service": service, "port": port, "status": "Active"}
        finally:
            db.close()

    def record_interaction(self, honeypot_code: str, attacker_ip: str, payload: str = "") -> Dict:
        """Attacker interacts with honeypot trap -> triggers deception telemetry."""
        db = SessionLocal()
        try:
            trap = db.query(HoneypotModel).filter_by(honeypot_code=honeypot_code).first()
            if not trap:
                # Try finding by ID if passed as numeric
                trap = db.query(HoneypotModel).first()
                if not trap:
                    raise ValueError(f"Honeypot trap {honeypot_code} not found")

            now_ts = time.time()
            now_str = datetime.datetime.now().strftime("%H:%M:%S")

            trap.status = "Triggered"
            trap.attacker_ip = attacker_ip
            trap.interactions += 1
            trap.interaction_time = now_str
            trap.last_payload = payload or f"PROBE /auth/{trap.service.lower()}"

            # Log agent terminal activity
            log = AgentDecisionModel(
                time_str=now_str,
                event_type="interaction",
                status="auto_approved",
                action="alert",
                target=attacker_ip,
                risk_score=75,
                reason=f"Attacker probing deception decoy {trap.service}",
                message=f"Attacker {attacker_ip} interacting with {trap.service} ({trap.honeypot_code}) — captured signature"
            )
            db.add(log)
            db.commit()

            # Feed synthetic flow events into the security engine so real detection & response occurs!
            # We generate repeated probe packets so brute-force or scan detectors fire on the attacker
            flow_batch = [
                FlowEvent(
                    ts=now_ts - (10 - i),
                    src_ip=attacker_ip,
                    dst_ip="192.168.1.1",
                    dst_port=22 if "SSH" in trap.service else (21 if "FTP" in trap.service else 23),
                    proto="tcp",
                    bytes_out=350,
                    bytes_in=120,
                    packets=4
                )
                for i in range(12)
            ]
            for f in flow_batch:
                engine_instance.ingest_flow(f)

            return {
                "id": trap.honeypot_code,
                "service": trap.service,
                "status": trap.status,
                "interactions": trap.interactions,
                "attacker_ip": attacker_ip,
                "last_trigger": trap.interaction_time
            }
        finally:
            db.close()


honeypot_service = HoneypotService()
