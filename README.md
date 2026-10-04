# pqready

Grade how ready a TLS endpoint is for post-quantum cryptography, and get a fix-first list.

```
$ pqready omaribrahim.me github.com canada.ca

  B    omaribrahim.me:443
       TLS        1.0 yes  1.1 yes  1.2 yes  1.3 yes
       browsers   X25519MLKEM768
       PQ groups  X25519MLKEM768 yes  SecP256r1MLKEM768 no  SecP384r1MLKEM1024 no  ...
       cert       ECDSA secp256r1 256, ecdsa-with-SHA256, issuer WE1, 84 days left, trusted
       + Negotiates X25519MLKEM768 with browser-style clients
       + Steers classical-first clients onto ML-KEM with a HelloRetryRequest
       P1 Legacy protocol enabled: TLSv1.0, TLSv1.1
       P2 Classical certificate signature (ecdsa-with-SHA256)

  C    github.com:443
       browsers   x25519
       P1 No post-quantum key exchange

  D    canada.ca:443
       TLS        1.0 no  1.1 no  1.2 yes  1.3 no
       P0 No TLS 1.3
```

## Why

**Harvest now, decrypt later.** Anyone can record encrypted traffic today and keep it until a
cryptographically relevant quantum computer can break the key exchange. So the key exchange is the
urgent part of the migration: a session negotiated with classical X25519 today stays readable to
whoever stored it. The Government of Canada roadmap (Cyber Centre ITSM.40.001) gives departments
until the end of 2031 for high-priority systems and 2035 for everything else; step one is knowing
where you stand.

Signatures are different. A forged signature only matters once the quantum computer exists, so a
classical certificate is a planning item, not an emergency. pqready ranks findings that way.

## How it works

Most scanners ask the local TLS library to connect and report what happened, so they can only see
the groups that library supports. pqready builds its own TLS 1.3 ClientHello byte by byte
([`tls13.py`](src/pqready/tls13.py)), sends it, and reads the server's first reply. That lets it ask
for any group, standard or draft, regardless of the OpenSSL installed.

Each target gets this probe matrix:

| Probe | ClientHello | Answers |
|---|---|---|
| Browser | offers X25519MLKEM768, x25519, P-256, P-384; key shares for the first two | What a current Chrome/Firefox/Safari actually gets |
| Classical-first | offers x25519 then X25519MLKEM768; key share for x25519 only | Does the server push old clients onto ML-KEM with a HelloRetryRequest? |
| Enumeration | one probe per group: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM768, MLKEM1024, X25519Kyber768Draft00 | Every post-quantum group the server accepts |
| Versions | normal handshakes pinned to TLS 1.0, 1.1, 1.2, 1.3 | Downgrade surface |
| Certificate | verified handshake, then unverified fallback | Signature algorithm (including ML-DSA), key, expiry, trust |

The handshake never completes, so the key shares only need to be well-formed. The ML-KEM public keys
are real FIPS 203 encodings (768 or 1024 coefficients below q = 3329, packed 12 bits each, plus a
seed) because servers run the FIPS 203 modulus check before encapsulating. Random bytes would fail it.

## Grades

| Grade | Meaning |
|---|---|
| A+ | Browsers get hybrid ML-KEM, no TLS 1.0/1.1, trusted certificate with 30+ days left |
| A | Browsers get hybrid ML-KEM |
| B | ML-KEM accepted but not preferred, or legacy versions still enabled |
| C | TLS 1.3, classical key exchange only (or only the retired Kyber draft) |
| D | No TLS 1.3, so no standard way to add post-quantum key exchange |
| F | Expired certificate, or nothing newer than TLS 1.1 |

Priorities: **P0** fix now, **P1** harvest-now-decrypt-later exposure, **P2** plan, **P3** hygiene.

## Usage

```bash
pip install -e .
pqready example.com                       # one host
pqready -f domains.txt --md report.md     # a list, with a Markdown migration report
pqready -f domains.txt --json out.json    # machine-readable
pqready example.com --connect 203.0.113.7 # scan the origin behind a CDN, keeping the SNI
pqready -f prod.txt --fail-under A        # CI gate: exit 1 if anything regresses
```

`--connect` matters more than it looks. A site behind Cloudflare negotiates ML-KEM at the edge, but
the hop from the edge to your origin is a separate TLS connection. Scanning the origin directly shows
whether the whole path is post-quantum.

## The lab

[`lab/`](lab) runs four Nginx endpoints in one hardened container (read-only filesystem, all
capabilities dropped except what Nginx needs, bound to loopback), one per rung of the migration:

| Endpoint | Config | Grade |
|---|---|---|
| `legacy.lab:8443` | TLS 1.0 to 1.2 only | F |
| `classic.lab:8444` | TLS 1.3, `X25519:prime256v1` | C |
| `hybrid.lab:8445` | `ssl_ecdh_curve X25519MLKEM768:X25519:...` | A+ |
| `fullpq.lab:8446` | hybrid ML-KEM **and** an ML-DSA-65 certificate chain | A+, quantum-safe signature |

The only change between C and A+ is one line of Nginx config on OpenSSL 3.5. The full-PQ endpoint
shows the end state: both the key exchange and the authentication are post-quantum, verified end to
end by a client that trusts the lab's ML-DSA root.

```bash
lab/gen-certs.sh                       # needs OpenSSL 3.5+ for ML-DSA
docker compose -f lab/compose.yml up -d
pqready --connect 127.0.0.1 --cafile lab/certs/lab-ca-bundle.pem \
  legacy.lab:8443 classic.lab:8444 hybrid.lab:8445 fullpq.lab:8446
```

## Tests

31 tests: FIPS 203 key encoding and the modulus check, ClientHello structure, ServerHello and
HelloRetryRequest parsing, every grading rule, and end-to-end lab checks, including one that
confirms the hand-built probe agrees with `openssl s_client` on the negotiated group.

```bash
pytest                                  # unit tests
PQREADY_LAB=1 pytest                    # plus the lab
```

CI runs both, building the lab PKI inside an OpenSSL 3.5 container.

## What it found (October 2026)

| Set | Targets | TLS 1.3 | Hybrid PQ for browsers |
|---|---|---|---|
| Canadian banks, government, telecom, universities | 23 | 19 (83%) | 10 (43%) |
| Security vendors exhibiting at SecTor 2026 | 21 | 20 (95%) | 15 (71%) |
| My own 5 production sites | 5 | 5 | 5, but 4 still accepted TLS 1.0/1.1 |

All six big Canadian banks negotiate hybrid ML-KEM. Only 2 of 7 government sites and 1 of 6
universities do, and none of the three federal sites in the set supports TLS 1.3 at all.

## Scope

pqready performs ordinary TLS handshakes, the same ones a browser makes, and reads only what a server
sends to any client. Scan systems you own or have permission to assess.

## License

MIT
