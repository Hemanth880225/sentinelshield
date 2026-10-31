"""Validated telemetry events produced by the collector (frozen, stdlib only)."""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass

PROTOS = {"tcp", "udp", "icmp"}


def parse_ip(value: str):
    return ipaddress.ip_address(value)  # raises ValueError


def is_private(value: str) -> bool:
    return parse_ip(value).is_private


@dataclass(frozen=True)
class FlowEvent:
    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    bytes_out: int = 0
    bytes_in: int = 0
    packets: int = 1
    src_mac: str = ""

    def __post_init__(self):
        parse_ip(self.src_ip); parse_ip(self.dst_ip)
        if not 0 <= self.dst_port <= 65535:
            raise ValueError("dst_port out of range")
        if self.proto not in PROTOS:
            raise ValueError("unsupported proto")
        if min(self.bytes_out, self.bytes_in, self.packets) < 0:
            raise ValueError("negative counter")


@dataclass(frozen=True)
class DnsEvent:
    ts: float
    src_ip: str
    qname: str
    qtype: str = "A"

    def __post_init__(self):
        parse_ip(self.src_ip)
        if not self.qname or len(self.qname) > 253:
            raise ValueError("invalid qname")


@dataclass(frozen=True)
class DeviceEvent:
    ts: float
    mac: str
    ip: str
    hostname: str = ""

    def __post_init__(self):
        parse_ip(self.ip)
        if len(self.mac.split(":")) != 6:
            raise ValueError("invalid mac")
