"""Correctness of the benchmark wrappers (round-trip, tamper rejection, resolution logging)."""

import pytest

from pqcap.algorithms import EcdsaP256, Ed25519, HmacSha256, build_algorithms
from pqcap.oqs_loader import load_oqs

oqs = load_oqs()

CFG = {
    "pq_signatures": [
        {"label": "ML-DSA-44", "candidates": ["ML-DSA-44"]},
        {"label": "Falcon-512", "candidates": ["FN-DSA-512", "Falcon-512"]},
        {"label": "Ghost", "candidates": ["NOT-A-MECHANISM"]},
    ],
    "stateful_signatures": [
        {"label": "LMS-SHA256-H5-W8", "candidates": ["LMS_SHA256_H5_W8"]},
        {"label": "XMSS-SHA2-10-256", "candidates": ["XMSS-SHA2_10_256"]},
        {"label": "NoStfl", "candidates": ["nope"]},
    ],
    "kems": [{"label": "ML-KEM-512", "candidates": ["ML-KEM-512"]}, {"label": "NoKem", "candidates": ["x"]}],
    "classical": ["ECDSA-P256", "Ed25519"],
    "symmetric": ["HMAC-SHA256-T16", "HMAC-SHA256-T32"],
    "hybrid": [{"label": "ECDSA-P256+ML-DSA-44", "parts": ["ECDSA-P256", "ML-DSA-44"]},
               {"label": "X+Ghost", "parts": ["ECDSA-P256", "Ghost"]}],
}


@pytest.fixture(scope="module")
def built():
    return build_algorithms(CFG, oqs)


def test_resolution_log(built):
    _, _, res = built
    by = {r.label: r for r in res}
    assert by["ML-DSA-44"].status == "ok" and by["ML-DSA-44"].impl_name == "ML-DSA-44"
    assert by["Falcon-512"].impl_name in ("FN-DSA-512", "Falcon-512")
    assert by["Ghost"].status == "unavailable" and "NOT-A-MECHANISM" in by["Ghost"].reason
    assert by["NoStfl"].status == "unavailable" and by["NoKem"].status == "unavailable"
    assert by["X+Ghost"].status == "unavailable" and "Ghost" in by["X+Ghost"].reason
    # LMS is verify-only in liboqs-python 0.16.0.2: must be logged, never silently used
    lms = by["LMS-SHA256-H5-W8"]
    assert lms.status in ("ok", "unavailable")
    if lms.status == "unavailable":
        assert "sign not supported" in lms.reason


def test_roundtrip_and_tamper(built):
    algs, kems, _ = built
    names = {a.name for a in algs}
    assert {"ML-DSA-44", "Falcon-512", "ECDSA-P256", "Ed25519", "HMAC-SHA256-T16",
            "ECDSA-P256+ML-DSA-44", "XMSS-SHA2-10-256"} <= names
    msg = b"capability-token-test-message"
    for a in algs:
        a.keygen()
        if a.kind == "stateful":
            a.ensure_budget(2)
        s = a.sign(msg)
        assert a.verify(msg, s), a.name
        assert not a.verify(msg + b"!", s), a.name
        bad = bytes([s[0] ^ 1]) + s[1:]
        assert not a.verify(msg, bad), a.name
        assert a.sk_bytes > 0 and a.pk_bytes >= 0


def test_sizes_reported(built):
    algs, kems, _ = built
    by = {a.name: a for a in algs}
    assert len(by["ECDSA-P256"].sign(b"m")) == 64          # raw r||s
    assert by["ECDSA-P256"].pk_bytes == 65 and by["ECDSA-P256"].sk_bytes == 32
    assert by["Ed25519"].pk_bytes == 32 and by["Ed25519"].sk_bytes == 32
    assert by["HMAC-SHA256-T16"].pk_bytes == 0 and len(by["HMAC-SHA256-T16"].sign(b"m")) == 16
    assert len(by["HMAC-SHA256-T32"].sign(b"m")) == 32
    h = by["ECDSA-P256+ML-DSA-44"]
    assert len(h.sign(b"m")) == 64 + len(by["ML-DSA-44"].sign(b"m"))
    assert h.pk_bytes == 65 + by["ML-DSA-44"].pk_bytes and h.sk_bytes > 32
    assert by["ML-DSA-44"].nominal_sig_bytes() >= len(by["ML-DSA-44"].sign(b"m"))
    k = kems[0]
    ct, ss = k.encaps()
    assert k.decaps(ct) == ss and k.pk_bytes > 0 and k.sk_bytes > 0
    k.keygen()


def test_hybrid_verify_before_sign():
    h = build_algorithms({**CFG, "pq_signatures": CFG["pq_signatures"][:1], "stateful_signatures": [],
                          "kems": []}, oqs)[0][-1]
    assert h.kind == "hybrid"
    h.keygen()
    s = h.sign(b"x")
    h._split = None                                     # fresh verifier path
    assert h.verify(b"x", s)


def test_stateful_rekey(built):
    algs, _, _ = built
    x = next(a for a in algs if a.kind == "stateful")
    pk0 = x.pk
    x.ensure_budget(10**9)                              # forces an untimed re-key
    assert x.pk != pk0 and x.sigs_remaining() > 0


def test_standalone_classical():
    for a in (EcdsaP256(), Ed25519(), HmacSha256(16)):
        assert a.verify(b"q", a.sign(b"q"))
