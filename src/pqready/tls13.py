"""Hand-built TLS 1.3 ClientHello probes.

Only the server's first flight matters here: the ServerHello (or a
HelloRetryRequest) says which key-exchange group the server picked. The
handshake is never finished, so the key shares sent only need to be
well-formed, not usable. That keeps the probe independent of whatever TLS
library is installed locally: it can ask for groups the local OpenSSL has
never heard of.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# IANA TLS Supported Groups registry (the ones that matter for this tool).
GROUPS: dict[int, str] = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    0x6399: "X25519Kyber768Draft00",
}
GROUP_IDS = {name: gid for gid, name in GROUPS.items()}

HYBRID_GROUPS = {0x11EB, 0x11EC, 0x11ED}
PURE_PQ_GROUPS = {0x0200, 0x0201, 0x0202}
DRAFT_GROUPS = {0x6399}  # pre-standard Kyber, being retired everywhere
PQ_GROUPS = HYBRID_GROUPS | PURE_PQ_GROUPS | DRAFT_GROUPS

# RFC 8446 4.1.3: a HelloRetryRequest is a ServerHello with this exact random.
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    40: "handshake_failure", 42: "bad_certificate", 47: "illegal_parameter",
    50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name",
    120: "no_application_protocol",
}

CIPHER_SUITES = (0x1301, 0x1302, 0x1303)
SIGNATURE_ALGORITHMS = (
    0x0403, 0x0503, 0x0603,  # ecdsa_secp{256,384,521}r1_sha{256,384,512}
    0x0804, 0x0805, 0x0806,  # rsa_pss_rsae_sha{256,384,512}
    0x0401, 0x0501, 0x0601,  # rsa_pkcs1_sha{256,384,512}
    0x0807,                  # ed25519
    0x0904, 0x0905, 0x0906,  # mldsa{44,65,87}
)

MLKEM_Q = 3329


def mlkem_public_key(k: int) -> bytes:
    """A syntactically valid ML-KEM encapsulation key (FIPS 203).

    It is k polynomials of 256 coefficients, each below q, packed 12 bits at a
    time, followed by a 32-byte seed. Servers run the FIPS 203 modulus check on
    it, so the coefficients must really be below q; random bytes would fail.
    Nobody holds the matching decapsulation key, which is fine: the probe hangs
    up after the ServerHello.
    """
    coeffs = [int.from_bytes(os.urandom(2), "big") % MLKEM_Q for _ in range(256 * k)]
    packed = bytearray()
    for a, b in zip(coeffs[0::2], coeffs[1::2], strict=True):
        packed += bytes((a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4))
    return bytes(packed) + os.urandom(32)


def _x25519() -> bytes:
    return x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()


def _ecdh(curve: ec.EllipticCurve) -> bytes:
    key = ec.generate_private_key(curve).public_key()
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def key_share(group: int) -> bytes:
    """Key share bytes for a group, in the order the hybrid drafts specify."""
    if group == 0x001D:
        return _x25519()
    if group == 0x0017:
        return _ecdh(ec.SECP256R1())
    if group == 0x0018:
        return _ecdh(ec.SECP384R1())
    if group == 0x11EC:  # ML-KEM first, then X25519
        return mlkem_public_key(3) + _x25519()
    if group == 0x11EB:  # ECDH first, then ML-KEM
        return _ecdh(ec.SECP256R1()) + mlkem_public_key(3)
    if group == 0x11ED:
        return _ecdh(ec.SECP384R1()) + mlkem_public_key(4)
    if group == 0x6399:  # X25519 first, then Kyber768 (same size as ML-KEM-768)
        return _x25519() + mlkem_public_key(3)
    if group in (0x0200, 0x0201, 0x0202):
        return mlkem_public_key({0x0200: 2, 0x0201: 3, 0x0202: 4}[group])
    raise ValueError(f"no key share generator for group 0x{group:04x}")


def _u8(b: bytes) -> bytes:
    return struct.pack("!B", len(b)) + b


def _u16(b: bytes) -> bytes:
    return struct.pack("!H", len(b)) + b


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!H", ext_type) + _u16(body)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def client_hello(sni: str | None, offer: list[int], shares: list[int]) -> bytes:
    """A complete TLS record carrying a TLS 1.3-only ClientHello."""
    exts = b""
    if sni and not _is_ip(sni):
        name = sni.encode("idna")
        exts += _ext(0x0000, _u16(b"\x00" + _u16(name)))
    exts += _ext(0x000A, _u16(b"".join(struct.pack("!H", g) for g in offer)))
    exts += _ext(0x000D, _u16(b"".join(struct.pack("!H", s) for s in SIGNATURE_ALGORITHMS)))
    exts += _ext(0x0010, _u16(_u8(b"h2") + _u8(b"http/1.1")))
    exts += _ext(0x002B, _u8(b"\x03\x04"))
    exts += _ext(0x002D, _u8(b"\x01"))  # psk_dhe_ke
    entries = b"".join(struct.pack("!H", g) + _u16(key_share(g)) for g in shares)
    exts += _ext(0x0033, _u16(entries))

    body = (
        b"\x03\x03"
        + os.urandom(32)
        + _u8(os.urandom(32))  # legacy_session_id, for middlebox compatibility
        + _u16(b"".join(struct.pack("!H", c) for c in CIPHER_SUITES))
        + b"\x01\x00"
        + _u16(exts)
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + _u16(handshake)


@dataclass
class ProbeResult:
    status: str  # "selected", "hrr", "alert", "not_tls13", "error"
    group: int | None = None
    alert: int | None = None
    error: str | None = None

    @property
    def group_name(self) -> str | None:
        if self.group is None:
            return None
        return GROUPS.get(self.group, f"0x{self.group:04x}")

    @property
    def alert_name(self) -> str | None:
        if self.alert is None:
            return None
        return ALERTS.get(self.alert, str(self.alert))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by server")
        buf += chunk
    return buf


def parse_server_hello(msg: bytes) -> ProbeResult:
    """Parse a ServerHello handshake body (without the 4-byte header)."""
    random = msg[2:34]
    pos = 34
    sid_len = msg[pos]
    pos += 1 + sid_len + 2 + 1  # session id, cipher suite, compression
    if pos + 2 > len(msg):
        return ProbeResult("not_tls13")
    ext_total = struct.unpack_from("!H", msg, pos)[0]
    pos += 2
    end = pos + ext_total
    version = None
    group = None
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack_from("!HH", msg, pos)
        data = msg[pos + 4 : pos + 4 + ext_len]
        if ext_type == 0x002B and len(data) >= 2:
            version = struct.unpack_from("!H", data)[0]
        elif ext_type == 0x0033 and len(data) >= 2:
            group = struct.unpack_from("!H", data)[0]
        pos += 4 + ext_len
    if version != 0x0304:
        return ProbeResult("not_tls13")
    return ProbeResult("hrr" if random == HRR_RANDOM else "selected", group=group)


def probe(
    host: str,
    port: int,
    offer: list[int],
    shares: list[int],
    sni: str | None = None,
    timeout: float = 5.0,
) -> ProbeResult:
    """Send one ClientHello and report what the server chose."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(client_hello(sni if sni is not None else host, offer, shares))
            buffered = b""
            while True:
                rec_type, _, rec_len = struct.unpack("!BHH", _recv_exact(sock, 5))
                payload = _recv_exact(sock, rec_len)
                if rec_type == 0x15:  # alert
                    return ProbeResult("alert", alert=payload[1] if len(payload) > 1 else None)
                if rec_type != 0x16:
                    return ProbeResult("error", error=f"unexpected record type {rec_type}")
                buffered += payload
                if len(buffered) < 4:
                    continue
                msg_len = int.from_bytes(buffered[1:4], "big")
                if len(buffered) < 4 + msg_len:
                    continue  # ServerHello split across records
                if buffered[0] != 0x02:
                    return ProbeResult("error", error=f"unexpected handshake type {buffered[0]}")
                return parse_server_hello(buffered[4 : 4 + msg_len])
    except (OSError, ConnectionError, struct.error, IndexError) as exc:
        return ProbeResult("error", error=str(exc) or exc.__class__.__name__)
