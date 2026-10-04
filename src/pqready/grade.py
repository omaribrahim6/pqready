"""Turn scan evidence into a grade and a fix-first list.

The ordering follows the threat, not the checklist. Key exchange is urgent
because of harvest-now-decrypt-later: traffic recorded today can be decrypted
once a cryptographically relevant quantum computer (CRQC) exists. Signatures
are not exposed that way (a forged signature only matters once the CRQC
exists), so classical certificates rank below classical key exchange.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field

from .scan import ScanResult
from .tls13 import DRAFT_GROUPS, GROUP_IDS

LETTERS = ["A+", "A", "B", "C", "D", "F"]

PRIORITY_MEANING = {
    "P0": "fix now",
    "P1": "fix this quarter: harvest-now-decrypt-later exposure",
    "P2": "plan for it",
    "P3": "hygiene",
}


@dataclass
class Finding:
    priority: str
    title: str
    detail: str


@dataclass
class Grade:
    letter: str
    findings: list[Finding] = field(default_factory=list)
    strengths: list[str] = field(default_factory=list)


def _worse(a: str, b: str) -> str:
    return LETTERS[max(LETTERS.index(a), LETTERS.index(b))]


def _down(letter: str) -> str:
    return LETTERS[min(LETTERS.index(letter) + 1, len(LETTERS) - 1)]


def grade(r: ScanResult) -> Grade:
    if not r.reachable:
        return Grade("ERR", [Finding("P0", "Unreachable", r.error or "no TLS handshake completed")])

    g = Grade("A")
    add = g.findings.append
    v = r.versions
    legacy = [name for name in ("TLSv1.0", "TLSv1.1") if v.get(name)]
    std_pq = [n for n, ok in r.pq_groups.items() if ok and GROUP_IDS[n] not in DRAFT_GROUPS]
    draft_pq = [n for n, ok in r.pq_groups.items() if ok and GROUP_IDS[n] in DRAFT_GROUPS]

    # Key exchange: the part an attacker can harvest today.
    if not r.tls13 and not v.get("TLSv1.2"):
        g.letter = "F"
        add(Finding("P0", "Only obsolete TLS versions", "Neither TLS 1.2 nor 1.3 is accepted."))
    elif not r.tls13:
        g.letter = "D"
        add(Finding("P0", "No TLS 1.3",
                    "Hybrid post-quantum key exchange only exists in TLS 1.3, so every session to this "
                    "host can be recorded now and decrypted later. Upgrade the TLS stack first."))
    elif not std_pq:
        g.letter = "C"
        if draft_pq:
            add(Finding("P1", "Only the pre-standard Kyber draft",
                        "X25519Kyber768Draft00 is being removed from browsers. Move to X25519MLKEM768 (FIPS 203)."))
        else:
            add(Finding("P1", "No post-quantum key exchange",
                        "TLS 1.3 is on but only classical groups are negotiated. Enable X25519MLKEM768 "
                        "(OpenSSL 3.5+: ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1)."))
    elif not r.browser_pq:
        g.letter = "B"
        add(Finding("P1", "Supports ML-KEM but picks classical for browsers",
                    f"The server accepts {', '.join(std_pq)} when forced, but chose "
                    f"{r.browser.group_name if r.browser else 'a classical group'} for a browser-style hello. "
                    "Put X25519MLKEM768 first in the server's group preference."))
    else:
        g.strengths.append(f"Negotiates {r.browser.group_name} with browser-style clients")
        if r.steers_to_pq:
            g.strengths.append("Steers classical-first clients onto ML-KEM with a HelloRetryRequest")

    if legacy:
        g.letter = _down(g.letter)
        add(Finding("P1", f"Legacy protocol enabled: {', '.join(legacy)}",
                    "Downgrade surface with no post-quantum option. Disable TLS 1.0 and 1.1."))

    # Certificate.
    c = r.cert
    if c is None:
        detail = "The handshake that should return the certificate failed."
        if ssl.OPENSSL_VERSION_INFO < (3, 5):
            # Older OpenSSL cannot negotiate ML-DSA signatures, so a post-quantum
            # certificate looks like a failed handshake from here.
            detail += (f" This machine runs {ssl.OPENSSL_VERSION}, which cannot verify ML-DSA certificates; "
                       "rerun with OpenSSL 3.5+ to see whether the server uses a post-quantum signature.")
        add(Finding("P2", "Certificate not read", detail))
    else:
        if c.days_left is not None and c.days_left < 0:
            g.letter = "F"
            add(Finding("P0", "Certificate expired", f"Expired {-c.days_left} days ago."))
        elif c.days_left is not None and c.days_left < 14:
            add(Finding("P1", "Certificate expires soon", f"{c.days_left} days left."))
        if c.trusted is False:
            g.letter = _worse(g.letter, "C")
            add(Finding("P0", "Certificate not trusted", c.trust_error or "chain did not verify"))
        if c.key_type == "RSA" and c.key_bits and c.key_bits < 2048:
            g.letter = _worse(g.letter, "C")
            add(Finding("P0", "Weak RSA key", f"{c.key_bits}-bit RSA. Use at least 2048, or ECDSA P-256."))
        if c.sig_alg == "sha1WithRSA":
            g.letter = _worse(g.letter, "C")
            add(Finding("P0", "SHA-1 signature", "Reissue the certificate with SHA-256 or better."))
        if c.pq_signature:
            g.strengths.append(f"Quantum-safe certificate signature ({c.sig_alg})")
        else:
            add(Finding("P2", f"Classical certificate signature ({c.sig_alg})",
                        "Not exposed to harvest-now-decrypt-later, so it ranks below key exchange. Track "
                        "ML-DSA certificate support at your CA and in browsers."))
        if c.lifetime_days and c.lifetime_days > 200 and c.trusted:
            add(Finding("P3", f"Long certificate lifetime ({c.lifetime_days} days)",
                        "CA/B Forum ballot SC-081 caps public TLS certificates at 200 days from March 2026, "
                        "100 from March 2027 and 47 from March 2029. Automated renewal is also the "
                        "crypto-agility you need to swap in post-quantum certificates later."))

    if g.letter == "A" and not legacy and c and c.trusted and (c.days_left or 0) >= 30:
        g.letter = "A+"
    g.findings.sort(key=lambda f: f.priority)
    return g
