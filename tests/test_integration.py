"""
SentinelShield — Integration & End-to-End Test Suite
Validates the full pipeline:
Telemetry -> Detectors -> Risk Scoring -> Policy Engine ->
Ed25519 Command Signing -> Local Enforcement Agent ->
FastAPI REST APIs -> Flask Dashboard Routes.
"""
import time
import unittest
from fastapi.testclient import TestClient

from app.database import (
    init_database, SessionLocal, DeviceModel, ThreatFindingModel,
    AgentDecisionModel, EnforcementRuleModel, HoneypotModel
)
from app.core.telemetry import FlowEvent, DnsEvent, DeviceEvent
from app.services.security_engine import SecurityEngine
from app.services.honeypot_service import HoneypotService
from fastapi_backend.api import app as fastapi_app
from flask_app.app import app as flask_app


class SentinelIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_database()
        cls.engine = SecurityEngine(tenant_id="test-tenant", collector_id="test-col")
        cls.honeypot_svc = HoneypotService()
        cls.api_client = TestClient(fastapi_app)
        cls.flask_client = flask_app.test_client()

    def test_01_telemetry_to_detection_to_enforcement_pipeline(self):
        """Test complete automated pipeline from incoming telemetry to signed firewall rule."""
        now_ts = time.time()
        attacker_ip = f"45.33.32.{int(time.time() * 1000) % 200 + 10}"

        # Ingest 15 brute force attempts on port 22 from external IP -> triggers brute force detector (risk > 70)
        flows = [
            FlowEvent(
                ts=now_ts + i * 0.2,
                src_ip=attacker_ip,
                dst_ip="192.168.1.1",
                dst_port=22,
                proto="tcp",
                bytes_out=300,
                packets=3
            )
            for i in range(15)
        ]

        for f in flows:
            self.engine.ingest_flow(f)

        db = SessionLocal()
        try:
            # Check finding was created
            finding = db.query(ThreatFindingModel).filter_by(src_ip=attacker_ip).first()
            self.assertIsNotNone(finding)
            self.assertEqual(finding.kind, "brute_force")
            self.assertGreater(finding.risk_score, 70)

            # Check agent decision was recorded as auto-approved block
            decision = db.query(AgentDecisionModel).filter_by(target=attacker_ip, status="auto_approved").first()
            self.assertIsNotNone(decision)
            self.assertEqual(decision.action, "block_ip")

            # Check signed command was executed by local enforcement agent
            rule = db.query(EnforcementRuleModel).filter_by(ip=attacker_ip).first()
            self.assertIsNotNone(rule)
            self.assertEqual(rule.action, "block_ip")
            self.assertEqual(rule.status, "active")
            self.assertTrue(len(rule.command_id) > 10)
        finally:
            db.close()

    def test_02_approval_required_human_in_the_loop_workflow(self):
        """Test human-in-the-loop authorization for sensitive action (isolate device)."""
        db = SessionLocal()
        try:
            # Create a pending decision that needs approval
            rec = AgentDecisionModel(
                time_str="12:00:00",
                event_type="detection",
                status="needs_approval",
                action="isolate_device",
                target="192.168.1.50",
                ttl_seconds=600,
                risk_score=65,
                reason="Policy requires approval for internal isolation",
                message="Suspicious activity on Smart Lock – Main Door"
            )
            db.add(rec)
            db.commit()
            d_id = rec.id
        finally:
            db.close()

        # Operator approves via security engine
        approve_res = self.engine.approve_decision(d_id, reviewer="lead-sec-ops")
        self.assertEqual(approve_res["outcome"], "applied")
        self.assertEqual(approve_res["target"], "192.168.1.50")

        # Verify decision record was updated in a new session
        db2 = SessionLocal()
        try:
            updated = db2.query(AgentDecisionModel).filter_by(id=d_id).first()
            self.assertEqual(updated.status, "approved")
            self.assertEqual(updated.reviewed_by, "lead-sec-ops")

            # Verify rule was applied in agent
            rule = db2.query(EnforcementRuleModel).filter_by(ip="192.168.1.50", action="isolate_device").first()
            self.assertIsNotNone(rule)
        finally:
            db2.close()

    def test_03_honeypot_interaction_and_deception(self):
        """Test honeypot decoy interaction, status update, and telemetry trigger."""
        res = self.honeypot_svc.record_interaction(
            honeypot_code="HP-1",
            attacker_ip="192.0.2.99",
            payload="SSH-2.0-ExploitPayload"
        )
        self.assertEqual(res["id"], "HP-1")
        self.assertEqual(res["status"], "Triggered")
        self.assertGreater(res["interactions"], 0)

        db = SessionLocal()
        try:
            trap = db.query(HoneypotModel).filter_by(honeypot_code="HP-1").first()
            self.assertEqual(trap.status, "Triggered")
            self.assertEqual(trap.attacker_ip, "192.0.2.99")
        finally:
            db.close()

    def test_04_fastapi_rest_endpoints(self):
        """Validate all core FastAPI endpoints return valid schemas and HTTP 200."""
        # 1. System Status
        res = self.api_client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("devices_online", data)
        self.assertIn("network_status", data)
        self.assertIn("threats_detected", data)
        self.assertIn("honeypots_active", data)

        # 2. Traffic
        res = self.api_client.get("/api/traffic")
        self.assertEqual(res.status_code, 200)
        traffic = res.json()
        self.assertIsInstance(traffic, list)
        if len(traffic) > 0:
            self.assertIn("source", traffic[0])
            self.assertIn("destination", traffic[0])
            self.assertIn("protocol", traffic[0])

        # 3. Threats
        res = self.api_client.get("/api/threats")
        self.assertEqual(res.status_code, 200)
        threats = res.json()
        self.assertIsInstance(threats, list)

        # 4. Honeypots
        res = self.api_client.get("/api/honeypots")
        self.assertEqual(res.status_code, 200)
        honeypots = res.json()
        self.assertIsInstance(honeypots, list)

        # 5. Agent Logs
        res = self.api_client.get("/api/logs")
        self.assertEqual(res.status_code, 200)
        logs = res.json()
        self.assertIsInstance(logs, list)

        # 6. Policy
        res = self.api_client.get("/api/policy")
        self.assertEqual(res.status_code, 200)
        pol = res.json()
        self.assertIn("autonomy", pol)
        self.assertIn("auto_threshold", pol)

        # 7. Enforcement Rules
        res = self.api_client.get("/api/enforcement/rules")
        self.assertEqual(res.status_code, 200)

        # 8. Enforcement Audit
        res = self.api_client.get("/api/enforcement/audit")
        self.assertEqual(res.status_code, 200)

    def test_05_fastapi_ingestion_and_simulation(self):
        """Test telemetry ingestion endpoints on FastAPI."""
        # Flow ingestion
        flow_payload = {
            "ts": time.time(),
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "proto": "tcp",
            "bytes_out": 500,
            "packets": 2
        }
        res = self.api_client.post("/api/telemetry/flow", json=flow_payload)
        self.assertEqual(res.status_code, 200)

        # DNS ingestion
        dns_payload = {
            "ts": time.time(),
            "src_ip": "10.0.0.5",
            "qname": "safe.internal.lan"
        }
        res = self.api_client.post("/api/telemetry/dns", json=dns_payload)
        self.assertEqual(res.status_code, 200)

        # Honeypot interaction via API
        hp_payload = {
            "honeypot_code": "HP-2",
            "attacker_ip": "198.51.100.88",
            "payload": "USER admin"
        }
        res = self.api_client.post("/api/honeypots/interact", json=hp_payload)
        self.assertEqual(res.status_code, 200)

    def test_06_flask_pages_and_design_preservation(self):
        """Ensure all Flask dashboard templates render with 200 OK and preserved brand."""
        pages = ["/", "/home", "/dashboard", "/traffic", "/threats", "/honeypots", "/agent_logs"]
        for p in pages:
            res = self.flask_client.get(p)
            self.assertEqual(res.status_code, 200, f"Page {p} returned status {res.status_code}")
            # Ensure visual brand SentinelShield is present
            self.assertIn(b"Sentinel", res.data)

    def test_07_flask_api_proxy_and_fallback(self):
        """Ensure Flask /api/* endpoints return real backend data."""
        res = self.flask_client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("devices_online", data)
        self.assertIn("network_status", data)

        res = self.flask_client.get("/api/threats")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.get_json(), list)


if __name__ == "__main__":
    unittest.main()
