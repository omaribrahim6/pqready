"""Run every probe against one target and collect the evidence."""

from __future__ import annotations

from dataclasses import dataclass, field

from .certs import CertInfo, fetch_cert, supported_versions
from .tls13 import GROUP_IDS, PQ_GROUPS, ProbeResult, probe

# What Chrome, Firefox and Safari send today: a hybrid share plus a classical
# fallback share, hybrid listed first.
BROWSER_OFFER = ["X25519MLKEM768", "x25519", "secp256r1", "secp384r1"]
BROWSER_SHARES = ["X25519MLKEM768", "x25519"]

# Every post-quantum group worth enumerating, newest standards first.
PQ_ENUM = [
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
    "MLKEM768",
    "MLKEM1024",
    "X25519Kyber768Draft00",
]


@dataclass
class Target:
    host: str
    port: int = 443
    connect: str | None = None  # dial this address instead, keeping host as SNI

    @property
    def label(self) -> str:
        via = f" via {self.connect}" if self.connect else ""
        return f"{self.host}:{self.port}{via}"

    @classmethod
    def parse(cls, spec: str, connect: str | None = None) -> Target:
        spec = spec.strip().removeprefix("https://").split("/", 1)[0]
        host, _, port = spec.rpartition(":") if spec.count(":") == 1 else (spec, "", "")
        return cls(host=host or spec, port=int(port) if port else 443, connect=connect)


@dataclass
class ScanResult:
    target: Target
    reachable: bool = False
    error: str | None = None
    versions: dict[str, bool | None] = field(default_factory=dict)
    browser: ProbeResult | None = None
    classical_first: ProbeResult | None = None
    pq_groups: dict[str, bool] = field(default_factory=dict)
    cert: CertInfo | None = None

    @property
    def tls13(self) -> bool:
        if self.versions.get("TLSv1.3"):
            return True
        return bool(self.browser and self.browser.status in ("selected", "hrr"))

    @property
    def browser_pq(self) -> bool:
        b = self.browser
        return bool(b and b.status == "selected" and b.group in PQ_GROUPS)

    @property
    def steers_to_pq(self) -> bool:
        c = self.classical_first
        return bool(c and c.status == "hrr" and c.group in PQ_GROUPS)


def _ids(names: list[str]) -> list[int]:
    return [GROUP_IDS[n] for n in names]


def scan(target: Target, cafile: str | None = None, timeout: float = 5.0) -> ScanResult:
    addr = target.connect or target.host
    sni = target.host
    result = ScanResult(target)

    result.browser = probe(addr, target.port, _ids(BROWSER_OFFER), _ids(BROWSER_SHARES), sni, timeout)
    if result.browser.status == "error":
        # Could be a TLS 1.2-only server that drops unknown hellos; check with a
        # normal handshake before calling it unreachable.
        result.versions = supported_versions(addr, target.port, sni, timeout)
        if not any(result.versions.values()):
            result.error = result.browser.error
            return result
    result.reachable = True

    result.classical_first = probe(
        addr, target.port, _ids(["x25519", "X25519MLKEM768"]), _ids(["x25519"]), sni, timeout
    )
    for name in PQ_ENUM:
        gid = GROUP_IDS[name]
        r = probe(addr, target.port, [gid], [gid], sni, timeout)
        result.pq_groups[name] = r.status == "selected" and r.group == gid
    if not result.versions:
        result.versions = supported_versions(addr, target.port, sni, timeout)
    result.cert = fetch_cert(addr, target.port, sni, cafile, timeout)
    return result
