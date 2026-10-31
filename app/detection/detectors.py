"""Rule/statistical detectors. Pure functions: events in, Findings out."""
from __future__ import annotations
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from app.core.telemetry import DeviceEvent, DnsEvent, FlowEvent, is_private


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: float          # 0..1
    src_ip: str
    evidence: dict = field(default_factory=dict)
    mitre: str = ""


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _window_stats(items: list[tuple[float, object]], window: float) -> tuple[int, int]:
    """Max (distinct keys, event count) inside any sliding window. items sorted by ts."""
    c: Counter = Counter()
    best_d = best_n = j = 0
    for i, (t, k) in enumerate(items):
        c[k] += 1
        while t - items[j][0] > window:
            c[items[j][1]] -= 1
            if c[items[j][1]] == 0:
                del c[items[j][1]]
            j += 1
        best_d = max(best_d, len(c)); best_n = max(best_n, i - j + 1)
    return best_d, best_n


def detect_port_scan(flows: Iterable[FlowEvent], window=60.0, min_ports=15) -> list[Finding]:
    g = defaultdict(list)
    for f in flows:
        if f.bytes_out <= 200:
            g[(f.src_ip, f.dst_ip)].append((f.ts, f.dst_port))
    out = []
    for (src, dst), items in g.items():
        items.sort()
        distinct, _ = _window_stats(items, window)
        if distinct >= min_ports:
            out.append(Finding("port_scan", _clamp(0.4 + distinct / (3 * min_ports)), src,
                               {"dst_ip": dst, "distinct_ports": distinct}, "T1046"))
    return out


def detect_brute_force(flows: Iterable[FlowEvent], ports=frozenset({21, 22, 23, 445, 3389}),
                       window=60.0, min_attempts=10) -> list[Finding]:
    g = defaultdict(list)
    for f in flows:
        if f.dst_port in ports and f.bytes_out < 2000:
            g[(f.src_ip, f.dst_ip, f.dst_port)].append((f.ts, 0))
    out = []
    for (src, dst, port), items in g.items():
        items.sort()
        _, n = _window_stats(items, window)
        if n >= min_attempts:
            out.append(Finding("brute_force", _clamp(0.5 + n / (4 * min_attempts)), src,
                               {"dst_ip": dst, "dst_port": port, "attempts": n}, "T1110"))
    return out


def detect_beaconing(flows: Iterable[FlowEvent], min_events=8, max_cv=0.15,
                     min_interval=5.0) -> list[Finding]:
    g = defaultdict(list)
    for f in flows:
        if not is_private(f.dst_ip):
            g[(f.src_ip, f.dst_ip, f.dst_port)].append(f.ts)
    out = []
    for (src, dst, port), ts in g.items():
        if len(ts) < min_events:
            continue
        ts.sort()
        iv = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.fmean(iv)
        if mean < min_interval:
            continue
        cv = statistics.pstdev(iv) / mean
        if cv <= max_cv:
            out.append(Finding("beaconing", _clamp(0.7 + 0.3 * (1 - cv / max_cv)), src,
                               {"dst_ip": dst, "dst_port": port, "interval_s": round(mean, 2),
                                "cv": round(cv, 4), "events": len(ts)}, "T1071"))
    return out


def detect_dns_tunnel(dns: Iterable[DnsEvent], min_label=30, min_entropy=3.5,
                      min_hits=5) -> list[Finding]:
    hits = defaultdict(list)
    for e in dns:
        label = e.qname.split(".")[0]
        if len(label) >= min_label and shannon_entropy(label) >= min_entropy:
            hits[e.src_ip].append(e.qname)
    return [Finding("dns_tunnel", _clamp(0.6 + len(q) / 50), src,
                    {"suspicious_queries": len(q), "sample": q[0]}, "T1071.004")
            for src, q in hits.items() if len(q) >= min_hits]


def detect_exfiltration(flows: Iterable[FlowEvent], baseline: dict[str, tuple[float, float]],
                        min_bytes=10_000_000, min_z=4.0) -> list[Finding]:
    tot = Counter()
    for f in flows:
        if not is_private(f.dst_ip):
            tot[f.src_ip] += f.bytes_out
    out = []
    for src, total in tot.items():
        mean, std = baseline.get(src, (0.0, 1.0))
        z = (total - mean) / max(std, 1.0)
        if total >= min_bytes and z >= min_z:
            out.append(Finding("exfiltration", _clamp(0.6 + 0.05 * z), src,
                               {"bytes_out_external": total, "z": round(z, 1)}, "T1041"))
    return out


def detect_unknown_devices(devices: Iterable[DeviceEvent], known_macs: set[str]) -> list[Finding]:
    known = {m.lower() for m in known_macs}
    return [Finding("unknown_device", 0.6 if not d.hostname else 0.4, d.ip,
                    {"mac": d.mac.lower(), "hostname": d.hostname}, "T1200")
            for d in devices if d.mac.lower() not in known]
