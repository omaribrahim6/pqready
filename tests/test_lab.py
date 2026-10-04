"""End-to-end checks against the Docker lab. Run with PQREADY_LAB=1 after
`lab/gen-certs.sh && docker compose -f lab/compose.yml up -d`."""

import os
import subprocess
from pathlib import Path

import pytest

from pqready.grade import grade
from pqready.scan import Target, scan

pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(os.environ.get("PQREADY_LAB") != "1", reason="lab not running"),
]

CA = str(Path(__file__).parent.parent / "lab" / "certs" / "lab-ca-bundle.pem")


@pytest.mark.parametrize(
    "spec,letter,browser_group",
    [
        ("legacy.lab:8443", "F", None),
        ("classic.lab:8444", "C", "x25519"),
        ("hybrid.lab:8445", "A+", "X25519MLKEM768"),
        ("fullpq.lab:8446", "A+", "X25519MLKEM768"),
    ],
)
def test_lab_grades(spec, letter, browser_group):
    r = scan(Target.parse(spec, connect="127.0.0.1"), cafile=CA)
    assert grade(r).letter == letter
    if browser_group:
        assert r.browser.group_name == browser_group


def test_fullpq_has_mldsa_chain():
    r = scan(Target.parse("fullpq.lab:8446", connect="127.0.0.1"), cafile=CA)
    assert r.cert.sig_alg == "ML-DSA-65"
    assert r.cert.trusted is True


def test_agrees_with_openssl():
    """The hand-built probe and OpenSSL's own client must report the same group."""
    out = subprocess.run(
        ["openssl", "s_client", "-connect", "127.0.0.1:8445", "-servername", "hybrid.lab",
         "-groups", "X25519MLKEM768:X25519"],
        input=b"", capture_output=True, timeout=10,
    ).stdout.decode()
    r = scan(Target.parse("hybrid.lab:8445", connect="127.0.0.1"), cafile=CA)
    assert f"Negotiated TLS1.3 group: {r.browser.group_name}" in out
