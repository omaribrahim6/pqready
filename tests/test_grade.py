from datetime import UTC, datetime, timedelta

from pqready.certs import CertInfo
from pqready.grade import grade
from pqready.scan import ScanResult, Target
from pqready.tls13 import ProbeResult

NOW = datetime.now(UTC)
MODERN = {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}


def cert(**kw):
    base = dict(
        sig_alg="ecdsa-with-SHA256", key_type="ECDSA secp256r1", key_bits=256,
        not_before=NOW - timedelta(days=10), not_after=NOW + timedelta(days=80), trusted=True,
    )
    base.update(kw)
    return CertInfo(**base)


def result(browser_group=0x11EC, pq=("X25519MLKEM768",), versions=MODERN, c=None, hrr=None):
    r = ScanResult(Target("example.test"), reachable=True, versions=dict(versions))
    r.browser = ProbeResult("selected", group=browser_group)
    r.classical_first = ProbeResult("hrr", group=hrr) if hrr else ProbeResult("selected", group=0x001D)
    r.pq_groups = {name: True for name in pq}
    r.cert = c or cert()
    return r


def test_hybrid_modern_site_gets_a_plus():
    g = grade(result())
    assert g.letter == "A+"
    assert [f.priority for f in g.findings] == ["P2"]  # only the classical signature note


def test_classical_only_is_c_with_p1():
    g = grade(result(browser_group=0x001D, pq=()))
    assert g.letter == "C"
    assert g.findings[0].priority == "P1"


def test_supported_but_not_preferred_is_b():
    g = grade(result(browser_group=0x001D))
    assert g.letter == "B"


def test_no_tls13_is_d():
    versions = dict(MODERN, **{"TLSv1.3": False})
    r = result(pq=(), versions=versions)
    r.browser = ProbeResult("alert", alert=70)
    assert grade(r).letter == "D"


def test_legacy_versions_cost_a_letter():
    versions = dict(MODERN, **{"TLSv1.0": True})
    assert grade(result(versions=versions)).letter == "B"


def test_expired_cert_fails():
    g = grade(result(c=cert(not_after=NOW - timedelta(days=2))))
    assert g.letter == "F"


def test_untrusted_cert_capped_at_c():
    g = grade(result(c=cert(trusted=False, trust_error="self-signed")))
    assert g.letter == "C"
    assert g.findings[0].priority == "P0"


def test_mldsa_cert_is_a_strength_not_a_finding():
    g = grade(result(c=cert(sig_alg="ML-DSA-65", key_type="ML-DSA-65", key_bits=None)))
    assert g.letter == "A+"
    assert not g.findings
    assert any("ML-DSA" in s for s in g.strengths)


def test_draft_kyber_only_is_c():
    g = grade(result(browser_group=0x6399, pq=("X25519Kyber768Draft00",)))
    assert g.letter == "C"
    assert "draft" in g.findings[0].title


def test_unreachable():
    r = ScanResult(Target("down.test"), reachable=False, error="timed out")
    assert grade(r).letter == "ERR"
