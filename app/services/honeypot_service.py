"""
SentinelShield — Honeypot & Deception Service
Manages dynamic deception traps, simulates/records attacker interactions,
and feeds deception telemetry into the core security engine with strict validation.
"""
from __future__ import annotations
import time
import datetime
from typing import Optional, List, Dict

from app.database import SessionLocal, HoneypotModel, AgentDecisionModel
from app.core.telemetry import FlowEvent
from app.services.security_engine import engine_instance


class HoneypotService:
    def list_honeypots(self, tenant_id: str = "default") -> List[Dict]:
        db = SessionLocal()
        try:
            traps = db.query(HoneypotModel).filter_by(tenant_id=tenant_id).all()
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

    def deploy_honeypot(self, service: str, port: int, tenant_id: str = "default") -> Dict:
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}. Port must be between 1 and 65535.")
        if not service or not service.strip():
            raise ValueError("Service name cannot be empty.")

        db = SessionLocal()
        try:
            existing_port = db.query(HoneypotModel).filter_by(tenant_id=tenant_id, port=port).first()
            if existing_port:
                raise ValueError(f"Port {port} is already assigned to {existing_port.service} ({existing_port.honeypot_code})")

            count = db.query(HoneypotModel).filter_by(tenant_id=tenant_id).count()
            code = f"HP-{count + 1}"
            new_trap = HoneypotModel(
                tenant_id=tenant_id,
                honeypot_code=code,
                service=service.strip(),
                port=port,
                status="Active",
                interactions=0
            )
            db.add(new_trap)

            now_str = datetime.datetime.now().strftime("%H:%M:%S")
            log = AgentDecisionModel(
                tenant_id=tenant_id,
                time_str=now_str,
                event_type="deployment",
                status="auto_approved",
                action="deploy_honeypot",
                target=f"0.0.0.0:{port}",
                risk_score=0,
                reason="Dynamic deception trap provisioned",
                message=f"Deploying {service.strip()} deception trap on port {port} ({code})"
            )
            db.add(log)
            db.commit()
            return {"id": code, "service": service.strip(), "port": port, "status": "Active"}
        finally:
            db.close()

    def record_interaction(self, honeypot_code: str, attacker_ip: str, payload: str = "", tenant_id: str = "default") -> Dict:
        """Attacker interacts with honeypot trap -> triggers deception telemetry."""
        if not honeypot_code or not honeypot_code.strip():
            raise ValueError("Honeypot code must be provided.")

        db = SessionLocal()
        try:
            trap = db.query(HoneypotModel).filter_by(
                tenant_id=tenant_id, honeypot_code=honeypot_code.strip()
            ).first()

            if not trap:
                # If passed numeric ID as string, try looking up by integer ID
                if honeypot_code.isdigit():
                    trap = db.query(HoneypotModel).filter_by(
                        tenant_id=tenant_id, id=int(honeypot_code)
                    ).first()

            if not trap:
                raise ValueError(f"Honeypot trap '{honeypot_code}' not found")

            now_ts = time.time()
            now_str = datetime.datetime.now().strftime("%H:%M:%S")

            trap.status = "Triggered"
            trap.attacker_ip = attacker_ip
            trap.interactions += 1
            trap.interaction_time = now_str
            trap.last_payload = payload or f"PROBE /auth/{trap.service.lower()}"

            log = AgentDecisionModel(
                tenant_id=tenant_id,
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

            # Feed flow events into engine so real detection and response occurs
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
