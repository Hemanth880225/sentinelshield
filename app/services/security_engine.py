"""
SentinelShield — Security Engine Service
Integrates Detection, Risk Scoring, Agentic Decision, Ed25519 Command Signing,
and Local Enforcement Agent.
"""
from __future__ import annotations
import time
import json
import datetime
import ipaddress
from typing import List, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core.telemetry import FlowEvent, DnsEvent, DeviceEvent, is_private
from app.detection import detectors as d
from app.orchestration.decision import (
    Action, Policy, Status, Risk, Proposal, Decision,
    score_findings, decide, validate_proposal, ENFORCED
)
from app.security.commands import CommandSigner, CommandVerifier, SignedCommand
from app.enforcement.agent import DryRunBackend, EnforcementAgent, NftBackend
from app.database import (
    SessionLocal, DeviceModel, TrafficFlowModel, DnsRecordModel,
    ThreatFindingModel, AgentDecisionModel, EnforcementRuleModel,
    EnforcementAuditModel, HoneypotModel, SystemPolicyModel
)

DISPLAY_NAMES = {
    "port_scan": "Port Scan",
    "brute_force": "Brute Force",
    "beaconing": "Beaconing (C2)",
    "dns_tunnel": "DNS Tunnel",
    "exfiltration": "Data Exfiltration",
    "unknown_device": "Unknown Device"
}


class SecurityEngine:
    def __init__(self, tenant_id: str = "default", collector_id: str = "col-primary"):
        self.tenant_id = tenant_id
        self.collector_id = collector_id
        
        # Ed25519 Keypair for cryptographic command signing
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        
        self.signer = CommandSigner(self._private_key)
        self.verifier = CommandVerifier(
            public_key=self._public_key,
            tenant_id=self.tenant_id,
            collector_id=self.collector_id
        )
        self.backend = DryRunBackend()
        self.agent = EnforcementAgent(
            verifier=self.verifier,
            backend=self.backend,
            protected=("127.0.0.1", "10.0.0.1", "192.168.1.1")
        )
        
        # In-memory sliding telemetry buffers for multi-event detection
        self._flow_buffer: list[FlowEvent] = []
        self._dns_buffer: list[DnsEvent] = []
        self._known_macs: set[str] = set()
        self._device_baselines: dict[str, tuple[float, float]] = {
            "192.168.1.10": (2_000_000.0, 500_000.0),
            "192.168.1.11": (2_000_000.0, 500_000.0),
        }
        self._init_known_devices()

    def _init_known_devices(self):
        try:
            db = SessionLocal()
            try:
                devices = db.query(DeviceModel).all()
                for dev in devices:
                    self._known_macs.add(dev.mac.lower())
            finally:
                db.close()
        except Exception:
            pass

    def get_current_policy(self, db) -> Policy:
        row = db.query(SystemPolicyModel).filter_by(tenant_id=self.tenant_id).first()
        if not row:
            row = db.query(SystemPolicyModel).first()
        if not row:
            return Policy()
        
        protected = tuple(p.strip() for p in row.protected_cidrs.split(",") if p.strip())
        return Policy(
            autonomy=row.autonomy,
            auto_threshold=row.auto_threshold,
            approve_threshold=row.approve_threshold,
            max_ttl=row.max_ttl,
            auto_isolate=row.auto_isolate,
            protected=protected
        )

    def ingest_flow(self, flow: FlowEvent, db=None) -> dict:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            now_dt = datetime.datetime.fromtimestamp(flow.ts) if flow.ts > 0 else datetime.datetime.now()
            time_str = now_dt.strftime("%H:%M:%S")

            # Persist traffic flow
            flow_record = TrafficFlowModel(
                ts=flow.ts,
                time_str=time_str,
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                proto=flow.proto.upper(),
                bytes_out=flow.bytes_out,
                bytes_in=flow.bytes_in,
                packets=flow.packets,
                src_mac=flow.src_mac
            )
            db.add(flow_record)

            # Buffer for window-based detectors
            self._flow_buffer.append(flow)
            if len(self._flow_buffer) > 200:
                self._flow_buffer = self._flow_buffer[-100:]

            # Run detection on buffer
            findings = []
            findings.extend(d.detect_port_scan(self._flow_buffer))
            findings.extend(d.detect_brute_force(self._flow_buffer))
            findings.extend(d.detect_beaconing(self._flow_buffer))
            findings.extend(d.detect_exfiltration(self._flow_buffer, self._device_baselines))

            results = self._process_findings(findings, db, time_str)
            db.commit()
            return {"flow_logged": True, "findings": len(findings), "actions": results}
        finally:
            if close_db:
                db.close()

    def ingest_dns(self, dns: DnsEvent, db=None) -> dict:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            now_dt = datetime.datetime.fromtimestamp(dns.ts) if dns.ts > 0 else datetime.datetime.now()
            time_str = now_dt.strftime("%H:%M:%S")

            dns_record = DnsRecordModel(
                ts=dns.ts,
                time_str=time_str,
                src_ip=dns.src_ip,
                qname=dns.qname,
                qtype=dns.qtype
            )
            db.add(dns_record)

            self._dns_buffer.append(dns)
            if len(self._dns_buffer) > 200:
                self._dns_buffer = self._dns_buffer[-100:]

            findings = d.detect_dns_tunnel(self._dns_buffer)
            results = self._process_findings(findings, db, time_str)
            db.commit()
            return {"dns_logged": True, "findings": len(findings), "actions": results}
        finally:
            if close_db:
                db.close()

    def ingest_device(self, dev: DeviceEvent, db=None) -> dict:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            now_dt = datetime.datetime.fromtimestamp(dev.ts) if dev.ts > 0 else datetime.datetime.now()
            time_str = now_dt.strftime("%H:%M:%S")

            # Check if unknown device
            findings = d.detect_unknown_devices([dev], self._known_macs)
            
            # Upsert device in database
            existing = db.query(DeviceModel).filter_by(mac=dev.mac).first()
            if not existing:
                new_dev = DeviceModel(
                    mac=dev.mac,
                    ip=dev.ip,
                    hostname=dev.hostname or "Unidentified Node",
                    device_type="Unknown Endpoint" if findings else "IoT Device",
                    status="online",
                    last_seen=now_dt
                )
                db.add(new_dev)
                if not findings:
                    self._known_macs.add(dev.mac.lower())
            else:
                existing.ip = dev.ip
                if dev.hostname:
                    existing.hostname = dev.hostname
                existing.last_seen = now_dt
                existing.status = "online"

            results = self._process_findings(findings, db, time_str)
            db.commit()
            return {"device_registered": True, "findings": len(findings), "actions": results}
        finally:
            if close_db:
                db.close()

    def _process_findings(self, findings: list[d.Finding], db, time_str: str) -> list[dict]:
        if not findings:
            return []

        actions_taken = []
        policy = self.get_current_policy(db)

        # 1. Store or update findings in DB
        for f in findings:
            # Check if active finding for this src_ip and kind exists
            existing = db.query(ThreatFindingModel).filter_by(
                src_ip=f.src_ip, kind=f.kind, status="active"
            ).first()

            sev_label = "High" if f.severity >= 0.7 else ("Medium" if f.severity >= 0.4 else "Low")
            display = DISPLAY_NAMES.get(f.kind, f.kind.replace("_", " ").title())

            if not existing:
                tf = ThreatFindingModel(
                    src_ip=f.src_ip,
                    target_device=f.evidence.get("dst_ip", "Network Infrastructure"),
                    kind=f.kind,
                    display_type=display,
                    severity=sev_label,
                    severity_score=round(f.severity, 2),
                    risk_score=round(f.severity * 100),
                    mitre=f.mitre,
                    evidence_json=json.dumps(f.evidence),
                    time_str=time_str,
                    status="active"
                )
                db.add(tf)

        # 2. Compute aggregate Risk scores per IP using noisy-OR algorithm
        risks = score_findings(findings)

        # 3. For each risk, run decision engine
        for r in risks:
            # Update threat finding risk scores for this src_ip
            db.query(ThreatFindingModel).filter_by(src_ip=r.src_ip, status="active").update({
                "risk_score": r.score
            })

            decision: Decision = decide(r, policy)
            prop = decision.proposal

            # Check if this exact action/target is already pending or active
            existing_decision = db.query(AgentDecisionModel).filter_by(
                action=prop.action.value, target=prop.target, status=decision.status.value
            ).first()

            if not existing_decision:
                msg = self._build_decision_message(decision)
                rec = AgentDecisionModel(
                    time_str=time_str,
                    event_type="enforcement" if decision.status == Status.AUTO_APPROVED and prop.action in ENFORCED else "detection",
                    status=decision.status.value,
                    action=prop.action.value,
                    target=prop.target,
                    ttl_seconds=prop.ttl_seconds,
                    risk_score=decision.risk_score,
                    reason="; ".join(decision.reasons) if decision.reasons else prop.reason,
                    message=msg
                )
                db.add(rec)
                db.flush()

                # If AUTO_APPROVED and action is ENFORCED, issue signed command and apply locally
                if decision.status == Status.AUTO_APPROVED and prop.action in ENFORCED:
                    exec_result = self._issue_and_enforce(
                        action=prop.action.value,
                        target=prop.target,
                        ttl_seconds=prop.ttl_seconds,
                        db=db,
                        decision_record=rec
                    )
                    actions_taken.append(exec_result)
                else:
                    actions_taken.append({
                        "decision_id": rec.id,
                        "status": decision.status.value,
                        "action": prop.action.value,
                        "target": prop.target
                    })

        return actions_taken

    def _issue_and_enforce(self, action: str, target: str, ttl_seconds: int, db, decision_record=None) -> dict:
        """Cloud signs Ed25519 command; local agent verifies and enforces."""
        now_ts = time.time()
        time_str = datetime.datetime.now().strftime("%H:%M:%S")

        # 1. Cloud Signer signs command
        signed_cmd = self.signer.issue(
            tenant_id=self.tenant_id,
            collector_id=self.collector_id,
            action=action,
            target=target,
            ttl_seconds=ttl_seconds
        )

        cmd_id = signed_cmd.payload["id"]
        if decision_record:
            decision_record.command_id = cmd_id

        # 2. Local Enforcement Agent applies command
        agent_outcome = self.agent.apply(signed_cmd)

        # 3. Audit trail in DB
        audit_rec = EnforcementAuditModel(
            ts=now_ts,
            time_str=time_str,
            command_id=cmd_id,
            outcome=agent_outcome["outcome"],
            detail=agent_outcome["detail"],
            action=action,
            target=target
        )
        db.add(audit_rec)

        # 4. If successfully applied, record active rule
        if agent_outcome["outcome"] == "applied":
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ttl_seconds)
            rule_rec = EnforcementRuleModel(
                action=action,
                ip=target,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                expires_at=expires_at,
                command_id=cmd_id,
                status="active"
            )
            db.add(rule_rec)

            # If isolated device, update device status in DB
            if action == "isolate_device":
                db.query(DeviceModel).filter_by(ip=target).update({"status": "quarantined"})

        return {
            "command_id": cmd_id,
            "outcome": agent_outcome["outcome"],
            "detail": agent_outcome["detail"],
            "action": action,
            "target": target
        }

    def approve_decision(self, decision_id: int, reviewer: str = "admin") -> dict:
        """Authorized administrator approves a pending decision."""
        db = SessionLocal()
        try:
            rec = db.query(AgentDecisionModel).filter_by(id=decision_id).first()
            if not rec:
                raise ValueError(f"Decision #{decision_id} not found")
            if rec.status != Status.NEEDS_APPROVAL.value:
                raise ValueError(f"Decision #{decision_id} is '{rec.status}', not pending approval")

            # Execute enforcement through signed workflow
            exec_res = self._issue_and_enforce(
                action=rec.action,
                target=rec.target,
                ttl_seconds=rec.ttl_seconds,
                db=db,
                decision_record=rec
            )

            rec.status = "approved"
            rec.reviewed_by = reviewer
            rec.reviewed_at = datetime.datetime.now(datetime.timezone.utc)
            rec.message = f"[Approved by {reviewer}] Firewall rule applied: {rec.action.upper()} {rec.target} (Signed Ed25519)"
            db.commit()
            return exec_res
        finally:
            db.close()

    def deny_decision(self, decision_id: int, reviewer: str = "admin", reason: str = "Admin override") -> dict:
        """Authorized administrator denies a pending decision."""
        db = SessionLocal()
        try:
            rec = db.query(AgentDecisionModel).filter_by(id=decision_id).first()
            if not rec:
                raise ValueError(f"Decision #{decision_id} not found")
            
            rec.status = "denied"
            rec.reviewed_by = reviewer
            rec.reviewed_at = datetime.datetime.now(datetime.timezone.utc)
            rec.message = f"[Denied by {reviewer}] Action {rec.action.upper()} on {rec.target} rejected: {reason}"
            db.commit()
            return {"decision_id": decision_id, "status": "denied", "reason": reason}
        finally:
            db.close()

    def expire_rules(self) -> int:
        """Tick enforcement agent expiry."""
        count = self.agent.expire()
        if count > 0:
            db = SessionLocal()
            try:
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                db.query(EnforcementRuleModel).filter(
                    EnforcementRuleModel.expires_at <= now_dt,
                    EnforcementRuleModel.status == "active"
                ).update({"status": "expired"})
                db.commit()
            finally:
                db.close()
        return count

    def _build_decision_message(self, decision: Decision) -> str:
        p = decision.proposal
        if decision.status == Status.AUTO_APPROVED:
            if p.action in ENFORCED:
                return f"Auto-defense applied: {p.action.value.upper()} on {p.target} (Risk: {decision.risk_score}%, TTL: {p.ttl_seconds}s)"
            return f"Action approved: {p.action.value.upper()} for {p.target}"
        elif decision.status == Status.NEEDS_APPROVAL:
            return f"Action requires authorization: {p.action.value.upper()} on {p.target} (Risk: {decision.risk_score}%, Policy threshold)"
        elif decision.status == Status.NOTIFY_ONLY:
            return f"Security alert: {p.action.value.upper()} on {p.target} (Notify-only, Risk: {decision.risk_score}%)"
        else:
            return f"Proposed action DENIED: {p.action.value.upper()} on {p.target} ({', '.join(decision.reasons)})"


# Singleton security engine instance
engine_instance = SecurityEngine()
