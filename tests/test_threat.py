"""Compromise matrix (K5/K6) and the S4-E vs S6 property differences, executed with real crypto."""

import hashlib
import hmac

import pytest

from pqcap import blast
from pqcap import envelope as ev
from pqcap.config import CONFIG, load_yaml
from pqcap.oqs_loader import load_oqs

ACFG = load_yaml(CONFIG / "actions.yaml")
THREAT = load_yaml(CONFIG / "threat.yaml")
CAT, ENV = ev.catalogue_from_config(ACFG), ev.envelope_from_config(ACFG)
INV, FW = ev.invariants_from_config(ACFG), ev.firmware_policy_from_config(ACFG)
REF = blast.reference_state_name(ACFG)


@pytest.fixture(scope="module")
def matrix():
    return blast.blast_compromise(CAT, ENV, FW, INV, THREAT, 8)


def _tot(df, comp, scheme, state=REF):
    return int(df[(df.compromise == comp) & (df.scheme == scheme) & (df.state == state)].accepted.sum())


def test_custody():
    assert blast.attacker_keys(THREAT, "C1") == {"session"}
    assert blast.attacker_keys(THREAT, "C2") == {"lorawan_ns"}
    assert blast.attacker_keys(THREAT, "C3") == {"policy_pq", "policy_mac"}
    assert blast.attacker_keys(THREAT, "C0") == set()                            # H5: agents hold no keys
    assert blast.attacker_keys(THREAT, "C4") == {"session", "receipt", "policy_mac"}
    assert set(THREAT["compromises"]) >= {"C0", "C1", "C2", "C3", "C4"}
    assert THREAT["status"].startswith("assumed")


def test_matrix(matrix):
    for st in blast.device_states(INV):
        for s in blast.SCHEMES:
            assert _tot(matrix, "C2", s, st) == 0 and _tot(matrix, "C3", s, st) == 0   # no session key
            assert _tot(matrix, "C1", s, st) <= _tot(matrix, "C1", "S4", st)
        assert _tot(matrix, "C1", "S4-E", st) == _tot(matrix, "C1", "S6", st)
        assert _tot(matrix, "C1+C3", "S6", st) == _tot(matrix, "C1+C3", "S4", st)      # envelope replaced
        assert _tot(matrix, "C1+C3", "S4-F", st) == _tot(matrix, "C1", "S4-F", st)    # firmware immune to C3
        c0 = {_tot(matrix, "C0", s, st) for s in blast.SCHEMES}
        assert c0 == {_tot(matrix, "C1", "S6", st)}                                # honest PDP = envelope policy
        assert _tot(matrix, "C4", "S4-E", st) == _tot(matrix, "C1", "S4", st)      # device holds policy_mac
        assert _tot(matrix, "C4", "S6", st) == _tot(matrix, "C1", "S6", st)        # device holds only pk_PA
    s4 = sum(a.targets * (a.max - a.min + 1) for a in CAT.values())
    assert _tot(matrix, "C1", "S4") == s4
    assert set(matrix[matrix.compromise == "C4"].scope) == {"one_device"}
    assert matrix[(matrix.compromise == "C1+C3") & (matrix.scheme == "S6")].attacker_replaced_envelope.all()
    assert not matrix[(matrix.compromise == "C1") & (matrix.scheme == "S6")].attacker_replaced_envelope.any()


def test_s6f_matrix(matrix):
    for st in blast.device_states(INV):
        assert _tot(matrix, "C1", "S6+F", st) == _tot(matrix, "C1", "S6", st)           # floor = envelope invariants
        assert _tot(matrix, "C1+C3", "S6+F", st) < _tot(matrix, "C1+C3", "S6", st)       # floor survives C3
        assert _tot(matrix, "C1+C3", "S6+F", st) <= _tot(matrix, "C1+C3+OP", "S6+F", st)
    calm = "alert=False,battery=above_floor"
    assert _tot(matrix, "C1+C3+OP", "S6+F", calm) - _tot(matrix, "C1+C3", "S6+F", calm) == 1   # the disable command
    assert blast.attacker_keys(THREAT, "C1+C3+OP") >= {"op_approval", "policy_pq", "session"}


def test_k6(matrix):
    k = blast.k6(matrix, REF, {"S4-E": 144, "S6": 2532})
    by = {r["compromise"]: r for r in k["rows"]}
    assert by["C1"]["ratio_s4e_s6"] == 1.0 and by["C2"]["ratio_note"] == "both 0"
    assert by["C4"]["ratio_s4e_s6"] > 1 and by["C4"]["scope"] == "one_device"
    assert k["answer"].endswith("differ (see table)")
    same = matrix[matrix.compromise != "C4"]
    assert blast.k6(same, REF, {"S4-E": 1, "S6": 1})["answer"].startswith("S4-E and S6 have the same")
    props = {p["property"]: p for p in k["properties"]}
    assert props["Blast radius under C1+C3 bounded below S4's"]["S4-F"].startswith("yes")
    assert props["Blast radius under C1+C3 bounded below S4's"]["S6"].startswith("no")
    m2 = matrix.copy()
    m2.loc[(m2.scheme == "S6") & (m2.compromise == "C1"), "accepted"] = 0
    k2 = blast.k6(m2, REF, {"S4-E": 1, "S6": 1})
    assert k2["answer"].endswith("differ (see table)")
    assert {r["compromise"]: r for r in k2["rows"]}["C1"]["ratio_note"] == "S6 is 0"


def test_third_party_verification():
    """Executable form of the K6 property: an S6 verifier holds only a public key and cannot forge;
    an S4-E verifier necessarily holds the key, and with it can install a permissive envelope."""
    oqs = load_oqs()
    blob = ev.encode_envelope(ENV)
    evil = ev.encode_envelope(ev.permissive_policy(CAT, ENV.handle))
    signer = oqs.Signature("ML-DSA-44")
    pk = signer.generate_keypair()
    sig = signer.sign(blob)
    verify = lambda b, s: oqs.Signature("ML-DSA-44").verify(b, s, pk)  # noqa: E731  (public key only)
    assert ev.install_envelope_s6(blob, sig, verify) == ENV
    assert ev.install_envelope_s6(evil, sig, verify) is None          # holder of pk cannot repurpose a signature
    key = b"p" * 32                                                    # the S4-E verifier's per-device key
    mac = hmac.new(key, blob, hashlib.sha256).digest()
    assert ev.install_envelope_s4e(blob, mac, key) == ENV
    forged = hmac.new(key, evil, hashlib.sha256).digest()             # same key that verifies, forges
    assert ev.install_envelope_s4e(evil, forged, key) == ev.permissive_policy(CAT, ENV.handle)
    assert ev.install_envelope_s4e(evil, mac, key) is None
