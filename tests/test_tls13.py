import struct

import pytest

from pqready.tls13 import (
    GROUP_IDS,
    HRR_RANDOM,
    MLKEM_Q,
    client_hello,
    key_share,
    mlkem_public_key,
    parse_server_hello,
)


def decode12(data: bytes) -> list[int]:
    out = []
    for i in range(0, len(data), 3):
        b0, b1, b2 = data[i : i + 3]
        out += [b0 | ((b1 & 0x0F) << 8), (b1 >> 4) | (b2 << 4)]
    return out


@pytest.mark.parametrize("k,size", [(2, 800), (3, 1184), (4, 1568)])
def test_mlkem_key_sizes_match_fips203(k, size):
    assert len(mlkem_public_key(k)) == size


def test_mlkem_key_passes_modulus_check():
    # FIPS 203 7.2: every decoded coefficient must be below q.
    pk = mlkem_public_key(3)
    coeffs = decode12(pk[:-32])
    assert len(coeffs) == 768
    assert max(coeffs) < MLKEM_Q


@pytest.mark.parametrize(
    "name,size",
    [
        ("x25519", 32),
        ("secp256r1", 65),
        ("X25519MLKEM768", 1184 + 32),
        ("SecP256r1MLKEM768", 65 + 1184),
        ("SecP384r1MLKEM1024", 97 + 1568),
    ],
)
def test_key_share_sizes(name, size):
    assert len(key_share(GROUP_IDS[name])) == size


def test_hybrid_share_order_is_mlkem_then_x25519():
    share = key_share(GROUP_IDS["X25519MLKEM768"])
    assert max(decode12(share[:1152])) < MLKEM_Q


def _extensions(record: bytes) -> dict[int, bytes]:
    assert record[0] == 0x16
    hs = record[5:]
    assert hs[0] == 0x01
    body = hs[4:]
    pos = 2 + 32
    pos += 1 + body[pos]
    pos += 2 + struct.unpack_from("!H", body, pos)[0]
    pos += 1 + body[pos]
    end = pos + 2 + struct.unpack_from("!H", body, pos)[0]
    pos += 2
    exts = {}
    while pos < end:
        t, n = struct.unpack_from("!HH", body, pos)
        exts[t] = body[pos + 4 : pos + 4 + n]
        pos += 4 + n
    return exts


def test_client_hello_offers_tls13_and_requested_groups():
    offer = [GROUP_IDS["X25519MLKEM768"], GROUP_IDS["x25519"]]
    exts = _extensions(client_hello("example.com", offer, offer))
    assert exts[0x002B] == b"\x02\x03\x04"
    assert exts[0x000A][2:] == b"\x11\xec\x00\x1d"
    assert b"example.com" in exts[0x0000]
    shares = exts[0x0033]
    assert struct.unpack_from("!HH", shares, 2) == (0x11EC, 1216)


def test_client_hello_skips_sni_for_ip():
    exts = _extensions(client_hello("127.0.0.1", [0x001D], [0x001D]))
    assert 0x0000 not in exts


def server_hello(random: bytes, group: int, version: int = 0x0304) -> bytes:
    exts = struct.pack("!HHH", 0x002B, 2, version)
    exts += struct.pack("!HHH", 0x0033, 2, group)
    return b"\x03\x03" + random + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack("!H", len(exts)) + exts


def test_parse_selected_group():
    r = parse_server_hello(server_hello(b"\x01" * 32, 0x11EC))
    assert (r.status, r.group_name) == ("selected", "X25519MLKEM768")


def test_parse_hello_retry_request():
    r = parse_server_hello(server_hello(HRR_RANDOM, 0x11EC))
    assert (r.status, r.group) == ("hrr", 0x11EC)


def test_parse_tls12_server_hello():
    r = parse_server_hello(server_hello(b"\x01" * 32, 0x001D, version=0x0303))
    assert r.status == "not_tls13"
