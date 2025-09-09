from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class PacketView:
    ts: float
    iface: str
    src: str
    dst: str
    proto: str
    sport: Optional[int]
    dport: Optional[int]
    length: int
    classification: str = 'unknown'
    summary: str = ''
    raw: bytes = field(repr=False, default=b'')
    scapy_pkt: Any = field(repr=False, default=None)
