"""Protocol versions and the certificate, through a normal TLS handshake."""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

SIG_ALGS = {
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
# SLH-DSA parameter sets occupy 2.16.840.1.101.3.4.3.20 through .31.
SLH_DSA_ARC = "2.16.840.1.101.3.4.3."
PQ_SIG_PREFIXES = ("ML-DSA", "SLH-DSA")

VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


@dataclass
class CertInfo:
    subject: str | None = None
    issuer: str | None = None
    sig_alg: str | None = None
    key_type: str | None = None
    key_bits: int | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    trusted: bool | None = None
    trust_error: str | None = None
    sans: list[str] = field(default_factory=list)

    @property
    def days_left(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - datetime.now(UTC)).days

    @property
    def lifetime_days(self) -> int | None:
        if self.not_before is None or self.not_after is None:
            return None
        return (self.not_after - self.not_before).days

    @property
    def pq_signature(self) -> bool:
        return bool(self.sig_alg and self.sig_alg.startswith(PQ_SIG_PREFIXES))


def _sig_name(oid: str) -> str:
    if oid in SIG_ALGS:
        return SIG_ALGS[oid]
    if oid.startswith(SLH_DSA_ARC) and 20 <= int(oid.rsplit(".", 1)[1]) <= 31:
        return "SLH-DSA"
    return oid


def _cn(name: x509.Name) -> str | None:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return name.rfc4514_string() or None


def parse_cert(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    info = CertInfo(
        subject=_cn(cert.subject),
        issuer=_cn(cert.issuer),
        sig_alg=_sig_name(cert.signature_algorithm_oid.dotted_string),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
    )
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info.sans = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    try:
        key = cert.public_key()
    except Exception:  # newer key types (e.g. ML-DSA) the library cannot load yet
        info.key_type = _sig_name(cert.public_key_algorithm_oid.dotted_string)
        return info
    if isinstance(key, rsa.RSAPublicKey):
        info.key_type, info.key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        info.key_type, info.key_bits = f"ECDSA {key.curve.name}", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        info.key_type, info.key_bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        info.key_type, info.key_bits = "Ed448", 456
    else:
        info.key_type = _sig_name(cert.public_key_algorithm_oid.dotted_string)
    return info


def _context(verify: bool, cafile: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.load_default_certs()
        if cafile:
            ctx.load_verify_locations(cafile)
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _handshake(host, port, sni, ctx, timeout) -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return ctx.wrap_socket(raw, server_hostname=sni)
    except Exception:
        raw.close()
        raise


def supported_versions(host: str, port: int, sni: str, timeout: float = 5.0) -> dict[str, bool | None]:
    """Which protocol versions the server accepts. None means the local
    OpenSSL could not even attempt that version."""
    result: dict[str, bool | None] = {}
    for label, version in VERSIONS:
        ctx = _context(False, None)
        try:
            with warnings.catch_warnings():  # probing old versions on purpose
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = version
                ctx.maximum_version = version
            if version < ssl.TLSVersion.TLSv1_2:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            result[label] = None
            continue
        try:
            with _handshake(host, port, sni, ctx, timeout):
                result[label] = True
        except ssl.SSLError as exc:
            # "no protocols available" means our side refused, not the server.
            result[label] = None if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() else False
        except OSError:
            result[label] = False
    return result


def fetch_cert(host: str, port: int, sni: str, cafile: str | None = None, timeout: float = 5.0) -> CertInfo | None:
    trusted, trust_error = True, None
    try:
        with _handshake(host, port, sni, _context(True, cafile), timeout) as tls:
            der = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        trusted, trust_error = False, exc.verify_message or str(exc)
        der = None
    except (ssl.SSLError, OSError):
        der = None
    if der is None:
        try:
            with _handshake(host, port, sni, _context(False, None), timeout) as tls:
                der = tls.getpeercert(binary_form=True)
        except (ssl.SSLError, OSError):
            return None
        if trusted:  # verified handshake failed for a non-certificate reason
            trusted = None
    info = parse_cert(der)
    info.trusted, info.trust_error = trusted, trust_error
    return info
