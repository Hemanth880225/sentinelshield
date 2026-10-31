"""Local enforcement agent: verify -> local policy -> backend -> audit. Fail-safe by design."""
from __future__ import annotations
import ipaddress
import subprocess
import time
from dataclasses import dataclass

from app.security.commands import CommandError, CommandVerifier, SignedCommand

ACTIONS = {"block_ip", "rate_limit", "isolate_device"}
SET_FOR = {"block_ip": "blocklist", "rate_limit": "ratelimit", "isolate_device": "isolated"}


class Backend:
    def add(self, action: str, ip: str, ttl: int) -> None: ...
    def remove(self, action: str, ip: str) -> None: ...


class DryRunBackend(Backend):
    def __init__(self):
        self.calls: list[tuple] = []

    def add(self, action, ip, ttl): self.calls.append(("add", action, ip, ttl))
    def remove(self, action, ip): self.calls.append(("remove", action, ip))


class NftBackend(Backend):
    """Requires a pre-provisioned `inet sentinel` table with timeout sets
    blocklist4/6, ratelimit4/6, isolated4/6. argv lists only; never a shell."""
    def __init__(self, run=subprocess.run):
        self._run = run

    @staticmethod
    def _argv(verb: str, action: str, ip: str, ttl: int | None) -> list[str]:
        a = ipaddress.ip_address(ip)          # re-validate right before use
        name = f"{SET_FOR[action]}{a.version}"
        elem = f"{{ {a}" + (f" timeout {int(ttl)}s" if ttl else "") + " }"
        return ["nft", verb, "element", "inet", "sentinel", name, elem]

    def add(self, action, ip, ttl): self._run(self._argv("add", action, ip, ttl), check=True, timeout=5)
    def remove(self, action, ip): self._run(self._argv("delete", action, ip, None), check=True, timeout=5)


@dataclass
class Rule:
    action: str
    ip: str
    expires_at: float


class EnforcementAgent:
    def __init__(self, verifier: CommandVerifier, backend: Backend,
                 protected: tuple[str, ...] = (), max_ttl: int = 3600, clock=time.time):
        self._v, self._b, self._max_ttl, self._clock = verifier, backend, max_ttl, clock
        self._protected = [ipaddress.ip_network(p, strict=False) for p in protected]
        self.rules: dict[tuple[str, str], Rule] = {}
        self.audit: list[dict] = []

    def _log(self, outcome: str, detail: str, cmd_id: str = "") -> dict:
        rec = {"ts": self._clock(), "command_id": cmd_id, "outcome": outcome, "detail": detail}
        self.audit.append(rec)
        return rec

    def _check_local(self, action: str, target: str, ttl: int) -> str | None:
        if action not in ACTIONS: return "action not supported"
        try: ip = ipaddress.ip_address(target)
        except ValueError: return "invalid target"
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
            return "non-routable target"
        if any(ip in n for n in self._protected): return "protected asset"
        if not 0 < ttl <= self._max_ttl: return "ttl out of range"
        return None

    def apply(self, cmd: SignedCommand) -> dict:
        try:
            p = self._v.verify(cmd)
        except CommandError as e:
            return self._log("rejected", str(e), cmd.payload.get("id", ""))
        bad = self._check_local(p["action"], p["target"], p["ttl_seconds"])
        if bad:
            return self._log("rejected", bad, p["id"])
        try:
            self._b.add(p["action"], p["target"], p["ttl_seconds"])
        except Exception as e:                         # backend failure must not crash the agent
            return self._log("failed", type(e).__name__, p["id"])
        self.rules[(p["action"], p["target"])] = Rule(p["action"], p["target"],
                                                       self._clock() + p["ttl_seconds"])
        return self._log("applied", f'{p["action"]} {p["target"]}', p["id"])

    def expire(self) -> int:
        """Remove lapsed rules. Called on a timer; also runs while the cloud is unreachable,
        so cloud loss never leaves permanent blocks and never drops active, unexpired ones."""
        now, n = self._clock(), 0
        for key, r in list(self.rules.items()):
            if r.expires_at <= now:
                try: self._b.remove(r.action, r.ip)
                except Exception: self._log("failed", "remove " + r.ip); continue
                del self.rules[key]; n += 1; self._log("expired", f"{r.action} {r.ip}")
        return n
