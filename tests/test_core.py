import random, string, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.core.telemetry import FlowEvent, DnsEvent, DeviceEvent
from app.detection import detectors as d
from app.orchestration.decision import (Action, Policy, Status, decide, propose,
                                         score_findings, validate_proposal)
from app.security.commands import CommandSigner, CommandVerifier, SignedCommand
from app.enforcement.agent import DryRunBackend, EnforcementAgent, NftBackend


class Clock:
    def __init__(self, t=1_000_000.0): self.t = t
    def __call__(self): return self.t


class TelemetryTests(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError): FlowEvent(0, "bad", "1.1.1.1", 80)
        with self.assertRaises(ValueError): FlowEvent(0, "10.0.0.1", "1.1.1.1", 70000)
        with self.assertRaises(ValueError): FlowEvent(0, "10.0.0.1", "1.1.1.1", 80, proto="gre")
        with self.assertRaises(ValueError): DeviceEvent(0, "aa:bb", "10.0.0.1")


class DetectorTests(unittest.TestCase):
    def test_port_scan(self):
        fl = [FlowEvent(i * 0.5, "45.33.32.9", "10.0.0.5", 1000 + i, bytes_out=60) for i in range(40)]
        f = d.detect_port_scan(fl)
        self.assertEqual(len(f), 1); self.assertEqual(f[0].src_ip, "45.33.32.9")

    def test_port_scan_slow_not_flagged(self):
        fl = [FlowEvent(i * 100, "45.33.32.9", "10.0.0.5", 1000 + i, bytes_out=60) for i in range(40)]
        self.assertEqual(d.detect_port_scan(fl), [])

    def test_brute_force_and_benign(self):
        fl = [FlowEvent(i, "45.33.33.7", "10.0.0.5", 22, bytes_out=300) for i in range(30)]
        self.assertEqual(d.detect_brute_force(fl)[0].kind, "brute_force")
        ok = [FlowEvent(i * 600, "10.0.0.20", "10.0.0.5", 22, bytes_out=300) for i in range(5)]
        self.assertEqual(d.detect_brute_force(ok), [])

    def test_beaconing(self):
        fl = [FlowEvent(i * 60.0 + (i % 2) * 0.5, "10.0.0.20", "93.184.216.50", 443) for i in range(12)]
        self.assertEqual(d.detect_beaconing(fl)[0].kind, "beaconing")
        rnd = random.Random(1)
        irr = [FlowEvent(sum(rnd.uniform(5, 300) for _ in range(i + 1)), "10.0.0.20", "93.184.216.50", 443)
               for i in range(12)]
        self.assertEqual(d.detect_beaconing(irr), [])

    def test_beaconing_ignores_internal(self):
        fl = [FlowEvent(i * 60.0, "10.0.0.20", "10.0.0.99", 443) for i in range(12)]
        self.assertEqual(d.detect_beaconing(fl), [])

    def test_dns_tunnel(self):
        rnd = random.Random(2)
        mk = lambda: "".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in range(40))
        ev = [DnsEvent(i, "10.0.0.20", f"{mk()}.evil.example") for i in range(8)]
        self.assertEqual(d.detect_dns_tunnel(ev)[0].kind, "dns_tunnel")
        norm = [DnsEvent(i, "10.0.0.20", "www.example.com") for i in range(50)]
        self.assertEqual(d.detect_dns_tunnel(norm), [])

    def test_exfiltration_uses_baseline(self):
        fl = [FlowEvent(i, "10.0.0.20", "45.33.32.80", 443, bytes_out=5_000_000) for i in range(6)]
        self.assertEqual(len(d.detect_exfiltration(fl, {"10.0.0.20": (1e6, 5e5)})), 1)
        self.assertEqual(d.detect_exfiltration(fl, {"10.0.0.20": (30e6, 10e6)}), [])  # normal for host

    def test_unknown_device(self):
        dev = [DeviceEvent(0, "AA:BB:CC:00:00:01", "10.0.0.50"), DeviceEvent(0, "aa:bb:cc:00:00:02", "10.0.0.51", "laptop")]
        f = d.detect_unknown_devices(dev, {"AA:BB:CC:00:00:02"})
        self.assertEqual([x.src_ip for x in f], ["10.0.0.50"])


class DecisionTests(unittest.TestCase):
    def finding(self, kind, sev, ip): return d.Finding(kind, sev, ip)

    def test_scoring_noisy_or(self):
        one = score_findings([self.finding("brute_force", 0.9, "1.2.3.4")])[0].score
        two = score_findings([self.finding("brute_force", 0.9, "1.2.3.4"),
                              self.finding("port_scan", 0.9, "1.2.3.4")])[0].score
        self.assertEqual(one, 76); self.assertGreater(two, one); self.assertLessEqual(two, 100)

    def test_external_attacker_auto_block(self):
        r = score_findings([self.finding("brute_force", 0.9, "45.33.32.9")])[0]
        dec = decide(r, Policy())
        self.assertEqual((dec.proposal.action, dec.status), (Action.BLOCK_IP, Status.AUTO_APPROVED))

    def test_isolation_needs_approval_by_default(self):
        r = score_findings([self.finding("exfiltration", 0.9, "10.0.0.20")])[0]
        dec = decide(r, Policy())
        self.assertEqual((dec.proposal.action, dec.status), (Action.ISOLATE_DEVICE, Status.NEEDS_APPROVAL))
        self.assertEqual(decide(r, Policy(auto_isolate=True)).status, Status.AUTO_APPROVED)

    def test_protected_asset_denied(self):
        r = score_findings([self.finding("exfiltration", 0.9, "10.0.0.1")])[0]
        self.assertEqual(decide(r, Policy(protected=("10.0.0.0/30",))).status, Status.DENIED)

    def test_autonomy_levels(self):
        r = score_findings([self.finding("brute_force", 0.9, "45.33.32.9")])[0]
        self.assertEqual(decide(r, Policy(autonomy="approval")).status, Status.NEEDS_APPROVAL)
        self.assertEqual(decide(r, Policy(autonomy="notify")).status, Status.NOTIFY_ONLY)

    def test_low_score_notify(self):
        r = score_findings([self.finding("unknown_device", 0.4, "10.0.0.50")])[0]
        self.assertEqual(decide(r, Policy()).proposal.action, Action.ALERT)

    def test_llm_proposal_is_validated(self):
        r = score_findings([self.finding("port_scan", 0.5, "45.33.32.9")])[0]
        pol = Policy(protected=("45.33.32.0/24",))
        bad = [{"action": "rm -rf", "target": "45.33.32.9", "ttl_seconds": 60},
               {"action": "block_ip", "target": "8.8.8.8", "ttl_seconds": 60},       # not the evidenced host
               {"action": "block_ip", "target": "45.33.32.9", "ttl_seconds": 60},   # protected
               {"action": "block_ip"}, "garbage"]
        for raw in bad:
            self.assertEqual(validate_proposal(raw if isinstance(raw, dict) else {}, r, pol).status, Status.DENIED)
        ok = validate_proposal({"action": "block_ip", "target": "45.33.32.9", "ttl_seconds": 999999},
                               score_findings([self.finding("brute_force", 0.9, "45.33.32.9")])[0], Policy())
        self.assertEqual(ok.proposal.ttl_seconds, 3600); self.assertIn("ttl clamped", ok.reasons)


class CommandAndAgentTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.key = Ed25519PrivateKey.generate()
        self.signer = CommandSigner(self.key, self.clock)
        self.mk_verifier = lambda t="t1", c="c1": CommandVerifier(self.key.public_key(), t, c, self.clock)
        self.backend = DryRunBackend()
        self.agent = EnforcementAgent(self.mk_verifier(), self.backend, protected=("10.0.0.1",), clock=self.clock)

    def cmd(self, **kw):
        a = dict(tenant_id="t1", collector_id="c1", action="block_ip", target="45.33.32.9", ttl_seconds=300)
        a.update(kw); return self.signer.issue(**a)

    def test_applied_and_audited(self):
        self.assertEqual(self.agent.apply(self.cmd())["outcome"], "applied")
        self.assertEqual(self.backend.calls, [("add", "block_ip", "45.33.32.9", 300)])

    def test_replay_rejected(self):
        c = self.cmd(); self.agent.apply(c)
        self.assertEqual(self.agent.apply(c)["detail"], "replay"); self.assertEqual(len(self.backend.calls), 1)

    def test_expired_rejected(self):
        c = self.cmd(); self.clock.t += 61
        self.assertEqual(self.agent.apply(c)["detail"], "expired")

    def test_tampered_rejected(self):
        c = self.cmd(); p = dict(c.payload, target="45.33.32.10")
        self.assertEqual(self.agent.apply(SignedCommand(p, c.signature))["detail"], "bad signature")

    def test_wrong_key_rejected(self):
        evil = CommandSigner(Ed25519PrivateKey.generate(), self.clock).issue("t1", "c1", "block_ip", "45.33.32.9", 60)
        self.assertEqual(self.agent.apply(evil)["detail"], "bad signature")

    def test_wrong_tenant_or_collector_rejected(self):
        self.assertEqual(self.agent.apply(self.cmd(tenant_id="t2"))["detail"], "wrong recipient")
        self.assertEqual(self.agent.apply(self.cmd(collector_id="c2"))["detail"], "wrong recipient")

    def test_local_policy_overrides_valid_signature(self):
        self.assertEqual(self.agent.apply(self.cmd(target="10.0.0.1"))["detail"], "protected asset")
        self.assertEqual(self.agent.apply(self.cmd(action="format_disk"))["detail"], "action not supported")
        self.assertEqual(self.agent.apply(self.cmd(ttl_seconds=10**6))["detail"], "ttl out of range")
        self.assertEqual(self.agent.apply(self.cmd(target="127.0.0.1"))["detail"], "non-routable target")
        self.assertEqual(self.backend.calls, [])

    def test_expiry_removes_rules_without_cloud(self):
        self.agent.apply(self.cmd())
        self.clock.t += 100; self.assertEqual(self.agent.expire(), 0)     # still active
        self.clock.t += 300; self.assertEqual(self.agent.expire(), 1)
        self.assertEqual(self.backend.calls[-1], ("remove", "block_ip", "45.33.32.9"))

    def test_backend_failure_is_contained(self):
        class Boom(DryRunBackend):
            def add(self, *a): raise OSError("nft missing")
        ag = EnforcementAgent(self.mk_verifier(), Boom(), clock=self.clock)
        self.assertEqual(ag.apply(self.cmd())["outcome"], "failed"); self.assertEqual(ag.rules, {})

    def test_nft_argv_no_shell_and_validated(self):
        calls = []
        NftBackend(run=lambda argv, **k: calls.append(argv)).add("block_ip", "45.33.32.9", 300)
        self.assertEqual(calls[0], ["nft", "add", "element", "inet", "sentinel", "blocklist4", "{ 45.33.32.9 timeout 300s }"])
        with self.assertRaises(ValueError):
            NftBackend(run=lambda *a, **k: None).add("block_ip", "1.1.1.1; reboot", 60)


if __name__ == "__main__":
    unittest.main()
