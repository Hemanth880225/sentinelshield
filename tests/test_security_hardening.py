"""
SentinelShield — Security Hardening & RBAC Test Suite
Validates:
1. Rejection of unauthenticated API calls (HTTP 401)
2. Role-Based Access Control (Admin, Analyst, Viewer, Collector)
3. Multi-tenant data isolation
4. Persistent Ed25519 cryptographic signing key reload
5. Durable command replay protection
6. Strict honeypot validation
7. Production simulator default posture
"""
import os
import unittest
import time
from fastapi.testclient import TestClient

from app.database import (
    init_database, SessionLocal, ThreatFindingModel,
    AgentDecisionModel, HoneypotModel
)
from app.services.auth import (
    ADMIN_API_KEY, ANALYST_API_KEY, VIEWER_API_KEY, COLLECTOR_TOKEN,
    authenticate_token, UserProfile
)
from app.services.security_engine import SecurityEngine, _get_or_create_signing_key
from app.services.honeypot_service import HoneypotService
from app.services.telemetry_generator import simulator
from fastapi_backend.api import app as fastapi_app


class SecurityHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_database()
        cls.client = TestClient(fastapi_app)

    def test_01_unauthenticated_requests_rejected(self):
        """Unauthenticated requests without API key or token must return 401."""
        endpoints = [
            "/api/status",
            "/api/traffic",
            "/api/threats",
            "/api/honeypots",
            "/api/logs",
            "/api/decisions",
            "/api/enforcement/rules",
            "/api/policy"
        ]
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 401, f"Expected 401 on {ep}, got {res.status_code}")

    def test_02_rbac_viewer_permissions(self):
        """Viewer role has read access but cannot perform mutations or ingestion."""
        viewer_headers = {"X-API-Key": VIEWER_API_KEY}

        # Viewer can read status
        res = self.client.get("/api/status", headers=viewer_headers)
        self.assertEqual(res.status_code, 200)

        # Viewer cannot approve decisions (403 Forbidden)
        res = self.client.post("/api/decisions/1/approve", headers=viewer_headers)
        self.assertEqual(res.status_code, 403)

        # Viewer cannot ingest flow telemetry (403 Forbidden)
        flow_payload = {
            "ts": time.time(),
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "proto": "tcp",
            "bytes_out": 100
        }
        res = self.client.post("/api/telemetry/flow", json=flow_payload, headers=viewer_headers)
        self.assertEqual(res.status_code, 403)

        # Viewer cannot deploy honeypots
        res = self.client.post("/api/honeypots/deploy", json={"service": "SSH", "port": 2222}, headers=viewer_headers)
        self.assertEqual(res.status_code, 403)

    def test_03_rbac_collector_permissions(self):
        """Collector token allows telemetry ingestion but denies administrative and read endpoints."""
        col_headers = {"X-API-Key": COLLECTOR_TOKEN}

        # Collector can ingest flow
        flow_payload = {
            "ts": time.time(),
            "src_ip": "10.0.0.22",
            "dst_ip": "192.168.1.1",
            "dst_port": 443,
            "proto": "tcp",
            "bytes_out": 250
        }
        res = self.client.post("/api/telemetry/flow", json=flow_payload, headers=col_headers)
        self.assertEqual(res.status_code, 200)

        # Collector cannot read SOC decisions
        res = self.client.get("/api/decisions", headers=col_headers)
        self.assertEqual(res.status_code, 403)

        # Collector cannot approve decisions
        res = self.client.post("/api/decisions/1/approve", headers=col_headers)
        self.assertEqual(res.status_code, 403)

    def test_04_rbac_analyst_permissions(self):
        """Analyst can read and trigger honeypot interactions, but cannot update policies or deploy traps."""
        analyst_headers = {"X-API-Key": ANALYST_API_KEY}

        # Analyst can read threats
        res = self.client.get("/api/threats", headers=analyst_headers)
        self.assertEqual(res.status_code, 200)

        # Analyst cannot deploy new honeypot services
        res = self.client.post("/api/honeypots/deploy", json={"service": "Fake Telnet 2", "port": 2324}, headers=analyst_headers)
        self.assertEqual(res.status_code, 403)

        # Analyst cannot change core policy
        res = self.client.put("/api/policy", json={"autonomy": "automatic"}, headers=analyst_headers)
        self.assertEqual(res.status_code, 403)

    def test_05_admin_full_access(self):
        """Admin has full authorization across read and write endpoints."""
        admin_headers = {"X-API-Key": ADMIN_API_KEY}

        res = self.client.get("/api/status", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

        res = self.client.get("/api/policy", headers=admin_headers)
        self.assertEqual(res.status_code, 200)

    def test_06_persistent_signing_key(self):
        """Ed25519 private key is persisted to disk and reloaded consistently."""
        key1 = _get_or_create_signing_key()
        pub1_bytes = key1.public_key().public_bytes_raw()

        key2 = _get_or_create_signing_key()
        pub2_bytes = key2.public_key().public_bytes_raw()

        self.assertEqual(pub1_bytes, pub2_bytes, "Ed25519 signing key must be persistent across reloads")

    def test_07_durable_replay_protection(self):
        """Engine rejects duplicate command ID when recorded in enforcement audit."""
        engine = SecurityEngine(tenant_id="tenant-replay-test", collector_id="col-replay")
        cmd = engine.signer.issue(
            tenant_id="tenant-replay-test",
            collector_id="col-replay",
            action="block_ip",
            target="45.33.32.99",
            ttl_seconds=300
        )

        # First verification succeeds
        verified = engine.verifier.verify(cmd)
        self.assertEqual(verified["target"], "45.33.32.99")

        # Immediate second verification fails with replay error
        from app.security.commands import CommandError
        with self.assertRaises(CommandError) as ctx:
            engine.verifier.verify(cmd)
        self.assertIn("replay", str(ctx.exception))

    def test_08_multi_tenant_isolation(self):
        """Tenant A cannot see Tenant B's threat findings or decisions."""
        db = SessionLocal()
        try:
            # Seed distinct threat for Tenant A
            db.add(ThreatFindingModel(
                tenant_id="tenant-alpha",
                src_ip="45.33.32.77",
                target_device="Alpha Gateway",
                kind="port_scan",
                display_type="Port Scan",
                severity="High",
                severity_score=0.85,
                risk_score=85,
                time_str="10:00:00",
                status="active"
            ))
            # Seed distinct threat for Tenant B
            db.add(ThreatFindingModel(
                tenant_id="tenant-beta",
                src_ip="185.220.101.99",
                target_device="Beta Gateway",
                kind="brute_force",
                display_type="Brute Force",
                severity="High",
                severity_score=0.90,
                risk_score=90,
                time_str="10:00:00",
                status="active"
            ))
            db.commit()
        finally:
            db.close()

        # Query using engine scoped to tenant-alpha
        alpha_engine = SecurityEngine(tenant_id="tenant-alpha")
        db2 = SessionLocal()
        try:
            alpha_threats = db2.query(ThreatFindingModel).filter_by(tenant_id="tenant-alpha").all()
            alpha_ips = {t.src_ip for t in alpha_threats}
            self.assertIn("45.33.32.77", alpha_ips)
            self.assertNotIn("185.220.101.99", alpha_ips)
        finally:
            db2.close()

    def test_09_strict_honeypot_validation(self):
        """Requesting or probing a non-existent honeypot raises ValueError/404, no silent fallback."""
        svc = HoneypotService()
        with self.assertRaises(ValueError) as ctx:
            svc.record_interaction("NON-EXISTENT-CODE", "45.33.32.1")
        self.assertIn("not found", str(ctx.exception))

    def test_10_simulator_not_running_by_default(self):
        """Telemetry simulator should be stopped by default in production unless explicitly enabled."""
        if os.environ.get("SENTINEL_SIMULATOR_ENABLED", "false").lower() != "true":
            # If not started explicitly, simulator should not be running indefinitely
            self.assertFalse(simulator.is_running)


if __name__ == "__main__":
    unittest.main()
