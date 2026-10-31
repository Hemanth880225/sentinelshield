"""Risk scoring + deterministic policy engine. LLM output is only ever a *proposal*
and must pass validate_proposal(); nothing here executes anything."""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
from enum import Enum

from app.detection.detectors import Finding

WEIGHTS = {"port_scan": 0.6, "brute_force": 0.85, "beaconing": 0.85,
           "dns_tunnel": 0.8, "exfiltration": 0.95, "unknown_device": 0.5}


class Action(str, Enum):
    BLOCK_IP = "block_ip"
    RATE_LIMIT = "rate_limit"
    ISOLATE_DEVICE = "isolate_device"
    DEPLOY_HONEYPOT = "deploy_honeypot"
    ALERT = "alert"


ENFORCED = {Action.BLOCK_IP, Action.RATE_LIMIT, Action.ISOLATE_DEVICE}


class Status(str, Enum):
    AUTO_APPROVED = "auto_approved"
    NEEDS_APPROVAL = "needs_approval"
    NOTIFY_ONLY = "notify_only"
    DENIED = "denied"


@dataclass(frozen=True)
class Risk:
    src_ip: str
    score: int                 # 0..100
    kinds: tuple[str, ...]


@dataclass(frozen=True)
class Proposal:
    action: Action
    target: str
    ttl_seconds: int
    reason: str


@dataclass(frozen=True)
class Decision:
    status: Status
    proposal: Proposal
    risk_score: int
    reasons: tuple[str, ...] = ()


@dataclass
class Policy:
    autonomy: str = "automatic"            # automatic | approval | notify
    auto_threshold: int = 70
    approve_threshold: int = 40
    max_ttl: int = 3600
    auto_isolate: bool = False             # isolation needs approval unless enabled
    protected: tuple[str, ...] = ()        # CIDRs / IPs that must never be touched
    allowed_actions: frozenset = field(default_factory=lambda: frozenset(Action))

    def is_protected(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return any(a in ipaddress.ip_network(p, strict=False) for p in self.protected)


def score_findings(findings: list[Finding]) -> list[Risk]:
    by_src: dict[str, list[Finding]] = {}
    for f in findings:
        by_src.setdefault(f.src_ip, []).append(f)
    out = []
    for src, fs in by_src.items():
        p = 1.0
        for f in fs:
            p *= 1 - WEIGHTS.get(f.kind, 0.5) * f.severity     # noisy-OR
        out.append(Risk(src, round(100 * (1 - p)), tuple(sorted({f.kind for f in fs}))))
    return sorted(out, key=lambda r: -r.score)


def propose(risk: Risk, policy: Policy) -> Proposal:
    ip = ipaddress.ip_address(risk.src_ip)
    kinds = set(risk.kinds)
    ttl = min(900, policy.max_ttl)
    reason = f"risk={risk.score} kinds={','.join(risk.kinds)}"
    if not ip.is_private:
        act = Action.RATE_LIMIT if kinds <= {"port_scan"} and risk.score < 60 else Action.BLOCK_IP
    elif kinds & {"beaconing", "dns_tunnel", "exfiltration"}:
        act = Action.ISOLATE_DEVICE
    else:
        act = Action.ALERT
    return Proposal(act, risk.src_ip, ttl, reason)


def decide(risk: Risk, policy: Policy, proposal: Proposal | None = None) -> Decision:
    p = proposal or propose(risk, policy)
    reasons: list[str] = []
    try:
        ip = ipaddress.ip_address(p.target)
    except ValueError:
        return Decision(Status.DENIED, p, risk.score, ("invalid target",))
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        return Decision(Status.DENIED, p, risk.score, ("non-routable target",))
    if p.action not in policy.allowed_actions:
        return Decision(Status.DENIED, p, risk.score, ("action not allowed by policy",))
    if p.action in ENFORCED and policy.is_protected(p.target):
        return Decision(Status.DENIED, p, risk.score, ("protected asset",))
    if not 0 < p.ttl_seconds <= policy.max_ttl:
        p = Proposal(p.action, p.target, min(max(p.ttl_seconds, 60), policy.max_ttl), p.reason)
        reasons.append("ttl clamped")
    if p.action not in ENFORCED:
        return Decision(Status.AUTO_APPROVED, p, risk.score, tuple(reasons))  # alerts/honeypots are non-destructive
    if policy.autonomy == "notify" or risk.score < policy.approve_threshold:
        return Decision(Status.NOTIFY_ONLY, p, risk.score, tuple(reasons))
    needs_human = (policy.autonomy == "approval" or risk.score < policy.auto_threshold
                   or (p.action is Action.ISOLATE_DEVICE and not policy.auto_isolate))
    return Decision(Status.NEEDS_APPROVAL if needs_human else Status.AUTO_APPROVED,
                    p, risk.score, tuple(reasons))


def validate_proposal(raw: dict, risk: Risk, policy: Policy) -> Decision:
    """Entry point for LLM/agent suggestions. Score comes from the deterministic
    engine, never from the model; malformed or unknown output is DENIED."""
    try:
        p = Proposal(Action(raw["action"]), str(raw["target"]), int(raw["ttl_seconds"]),
                     str(raw.get("reason", "llm"))[:200])
    except (KeyError, ValueError, TypeError):
        return Decision(Status.DENIED, Proposal(Action.ALERT, risk.src_ip, 60, "malformed"),
                        risk.score, ("malformed proposal",))
    if p.target != risk.src_ip:
        return Decision(Status.DENIED, p, risk.score, ("target differs from evidence",))
    return decide(risk, policy, p)
