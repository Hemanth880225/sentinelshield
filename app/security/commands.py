"""Ed25519-signed, expiring, replay-protected commands (cloud signs, agent verifies)."""
from __future__ import annotations
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class CommandError(Exception):
    pass


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class SignedCommand:
    payload: dict
    signature: str  # hex


class CommandSigner:
    def __init__(self, key: Ed25519PrivateKey, clock=time.time):
        self._key, self._clock = key, clock

    def issue(self, tenant_id: str, collector_id: str, action: str, target: str,
              ttl_seconds: int, valid_for: int = 60) -> SignedCommand:
        now = int(self._clock())
        payload = {"id": str(uuid.uuid4()), "tenant_id": tenant_id, "collector_id": collector_id,
                   "action": action, "target": target, "ttl_seconds": ttl_seconds,
                   "issued_at": now, "expires_at": now + valid_for, "nonce": secrets.token_hex(16)}
        return SignedCommand(payload, self._key.sign(canonical(payload)).hex())


class CommandVerifier:
    REQUIRED = ("id", "tenant_id", "collector_id", "action", "target", "ttl_seconds",
                "issued_at", "expires_at", "nonce")

    def __init__(self, public_key: Ed25519PublicKey, tenant_id: str, collector_id: str,
                 clock=time.time, max_skew: int = 30,
                 durable_replay_check: Optional[Callable[[str], bool]] = None):
        self._pub, self._tenant, self._collector = public_key, tenant_id, collector_id
        self._clock, self._skew = clock, max_skew
        self._seen: dict[str, int] = {}
        self._durable_replay_check = durable_replay_check

    def verify(self, cmd: SignedCommand) -> dict:
        p = cmd.payload
        if not all(k in p for k in self.REQUIRED):
            raise CommandError("malformed")
        try:
            self._pub.verify(bytes.fromhex(cmd.signature), canonical(p))
        except (InvalidSignature, ValueError):
            raise CommandError("bad signature")
        if p["tenant_id"] != self._tenant or p["collector_id"] != self._collector:
            raise CommandError("wrong recipient")
        now = self._clock()
        if p["issued_at"] > now + self._skew:
            raise CommandError("issued in future")
        if p["expires_at"] <= now:
            raise CommandError("expired")
        self._seen = {n: e for n, e in self._seen.items() if e > now}   # purge memory cache
        if p["nonce"] in self._seen:
            raise CommandError("replay")
        if self._durable_replay_check and self._durable_replay_check(p.get("id", "")):
            raise CommandError("replay")
        self._seen[p["nonce"]] = p["expires_at"]
        return p
