"""Uniform keygen/sign/verify wrappers and runtime algorithm resolution.

Every wrapper exposes:
    keygen()            -> None   (creates a fresh key pair, timed)
    sign(msg)           -> bytes  (uses the current key pair, timed)
    verify(msg, sig)    -> bool   (timed)
    pk_bytes, sk_bytes  -> int    (sizes of the current key pair as serialised)
    kind                -> "pq" | "stateful" | "classical" | "symmetric" | "hybrid"
and `name` (report label) / `impl_name` (exact library mechanism name).
"""

from __future__ import annotations

import hmac as _hmac
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as c_hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

P256_COORD = 32  # bytes per coordinate / scalar for secp256r1


@dataclass
class Resolution:
    label: str
    kind: str
    status: str  # "ok" | "unavailable" | "partial"
    impl_name: str = ""
    reason: str = ""
    candidates: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- liboqs
class OqsSig:
    kind = "pq"

    def __init__(self, oqs, label: str, impl_name: str):
        self.oqs, self.name, self.impl_name = oqs, label, impl_name
        self._signer = oqs.Signature(impl_name)
        self._verifier = oqs.Signature(impl_name)
        self.pk = self._signer.generate_keypair()
        self.details = dict(self._signer.details)

    def keygen(self):
        self.pk = self._signer.generate_keypair()

    def sign(self, msg: bytes) -> bytes:
        return self._signer.sign(msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        return self._verifier.verify(msg, sig, self.pk)

    @property
    def pk_bytes(self) -> int:
        return len(self.pk)

    @property
    def sk_bytes(self) -> int:
        return len(self._signer.export_secret_key())

    def nominal_sig_bytes(self) -> int:
        return int(self.details["length_signature"])


class OqsStatefulSig(OqsSig):
    """Stateful HBS. The key is regenerated (untimed) via `ensure_budget`."""

    kind = "stateful"

    def __init__(self, oqs, label: str, impl_name: str):
        self.oqs, self.name, self.impl_name = oqs, label, impl_name
        self._signer = oqs.StatefulSignature(impl_name)
        self._verifier = oqs.StatefulSignature(impl_name)
        self.pk = self._signer.generate_keypair()
        self.details = dict(self._signer.details)

    def sigs_remaining(self) -> int:
        return int(self._signer.sigs_remaining())

    def ensure_budget(self, n: int):
        if self.sigs_remaining() < n:
            self._signer = self.oqs.StatefulSignature(self.impl_name)
            self.pk = self._signer.generate_keypair()

    def keygen(self):
        self._signer = self.oqs.StatefulSignature(self.impl_name)
        self.pk = self._signer.generate_keypair()

    @property
    def sk_bytes(self) -> int:
        return int(self.details["length_secret_key"])


class OqsKem:
    kind = "kem"

    def __init__(self, oqs, label: str, impl_name: str):
        self.name, self.impl_name = label, impl_name
        self._kem = oqs.KeyEncapsulation(impl_name)
        self._enc = oqs.KeyEncapsulation(impl_name)
        self.pk = self._kem.generate_keypair()
        self.details = dict(self._kem.details)

    def keygen(self):
        self.pk = self._kem.generate_keypair()

    def encaps(self):
        return self._enc.encap_secret(self.pk)

    def decaps(self, ct: bytes) -> bytes:
        return self._kem.decap_secret(ct)

    @property
    def pk_bytes(self) -> int:
        return len(self.pk)

    @property
    def sk_bytes(self) -> int:
        return len(self._kem.export_secret_key())


# ---------------------------------------------------------------- classical
class EcdsaP256:
    """ECDSA-P256/SHA-256. Signatures are carried as fixed 64-byte r||s
    (IEEE P1363 / COSE encoding); DER<->raw conversion is inside the timed call."""

    kind = "classical"
    name = impl_name = "ECDSA-P256"

    def __init__(self):
        self.keygen()

    def keygen(self):
        self.sk = ec.generate_private_key(ec.SECP256R1())
        self.pub = self.sk.public_key()

    def sign(self, msg: bytes) -> bytes:
        r, s = decode_dss_signature(self.sk.sign(msg, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(P256_COORD, "big") + s.to_bytes(P256_COORD, "big")

    def verify(self, msg: bytes, sig: bytes) -> bool:
        r = int.from_bytes(sig[:P256_COORD], "big")
        s = int.from_bytes(sig[P256_COORD:], "big")
        try:
            self.pub.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @property
    def pk_bytes(self) -> int:  # SEC1 uncompressed point
        return len(self.pub.public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint))

    @property
    def sk_bytes(self) -> int:  # raw private scalar
        return len(self.sk.private_numbers().private_value.to_bytes(P256_COORD, "big"))


class Ed25519:
    kind = "classical"
    name = impl_name = "Ed25519"

    def __init__(self):
        self.keygen()

    def keygen(self):
        self.sk = ed25519.Ed25519PrivateKey.generate()
        self.pub = self.sk.public_key()

    def sign(self, msg: bytes) -> bytes:
        return self.sk.sign(msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        try:
            self.pub.verify(sig, msg)
            return True
        except Exception:
            return False

    @property
    def pk_bytes(self) -> int:
        return len(self.pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    @property
    def sk_bytes(self) -> int:
        return len(self.sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption()))


class HmacSha256:
    """HMAC-SHA256 truncated to `tag_len` bytes; 32-byte pre-shared key, no public key."""

    kind = "symmetric"
    KEY_LEN = 32

    def __init__(self, tag_len: int):
        self.tag_len = tag_len
        self.name = self.impl_name = f"HMAC-SHA256-T{tag_len}"
        self.keygen()

    def keygen(self):
        self.key = os.urandom(self.KEY_LEN)

    def sign(self, msg: bytes) -> bytes:
        h = c_hmac.HMAC(self.key, hashes.SHA256())
        h.update(msg)
        return h.finalize()[: self.tag_len]

    def verify(self, msg: bytes, sig: bytes) -> bool:
        h = c_hmac.HMAC(self.key, hashes.SHA256())
        h.update(msg)
        return _hmac.compare_digest(h.finalize()[: self.tag_len], sig)

    pk_bytes = 0

    @property
    def sk_bytes(self) -> int:
        return len(self.key)


class Hybrid:
    """Concatenated signature: sig_a || sig_b; both must verify (AND-combiner)."""

    kind = "hybrid"

    def __init__(self, label: str, a, b):
        self.name, self.a, self.b = label, a, b
        self.impl_name = f"{a.impl_name}+{b.impl_name}"
        self._split = None

    def keygen(self):
        self.a.keygen()
        self.b.keygen()

    def sign(self, msg: bytes) -> bytes:
        sa = self.a.sign(msg)
        self._split = len(sa)
        return sa + self.b.sign(msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        k = self._split if self._split is not None else len(self.a.sign(msg))
        return self.a.verify(msg, sig[:k]) and self.b.verify(msg, sig[k:])

    @property
    def pk_bytes(self) -> int:
        return self.a.pk_bytes + self.b.pk_bytes

    @property
    def sk_bytes(self) -> int:
        return self.a.sk_bytes + self.b.sk_bytes


# ---------------------------------------------------------------- resolution
def _resolve_oqs(entries, enabled, kind, label_key="label"):
    out = []
    for e in entries:
        hit = next((c for c in e["candidates"] if c in enabled), None)
        if hit:
            out.append(Resolution(e[label_key], kind, "ok", hit, "", list(e["candidates"])))
        else:
            out.append(Resolution(e[label_key], kind, "unavailable", "",
                                  f"none of {e['candidates']} in liboqs enabled {kind} mechanisms",
                                  list(e["candidates"])))
    return out


def build_algorithms(cfg: dict, oqs):
    """Return (sig_algorithms: list, kems: list, resolutions: list[Resolution])."""
    sig_enabled = set(oqs.get_enabled_sig_mechanisms())
    stfl_enabled = set(oqs.get_enabled_stateful_sig_mechanisms())
    kem_enabled = set(oqs.get_enabled_kem_mechanisms())

    res: list[Resolution] = []
    algs: dict[str, object] = {}

    for r in _resolve_oqs(cfg["pq_signatures"], sig_enabled, "pq"):
        res.append(r)
        if r.status == "ok":
            algs[r.label] = OqsSig(oqs, r.label, r.impl_name)

    for r in _resolve_oqs(cfg["stateful_signatures"], stfl_enabled, "stateful"):
        if r.status == "ok":
            a = OqsStatefulSig(oqs, r.label, r.impl_name)
            # Probe sign support: liboqs-python may expose a mechanism verify-only.
            try:
                a.sign(b"probe")
                a.keygen()
                algs[r.label] = a
            except NotImplementedError as exc:
                d = a.details
                r.status = "unavailable"
                r.reason = (f"sign not supported by liboqs-python ({exc}); no signature can be produced, "
                            f"so sign/verify are not measured. liboqs nominal sizes (NOT measured): "
                            f"pk={d['length_public_key']} sk={d['length_secret_key']} sig={d['length_signature']}")
        res.append(r)

    kems = []
    for r in _resolve_oqs(cfg["kems"], kem_enabled, "kem"):
        res.append(r)
        if r.status == "ok":
            kems.append(OqsKem(oqs, r.label, r.impl_name))

    for c in cfg["classical"]:
        algs[c] = {"ECDSA-P256": EcdsaP256, "Ed25519": Ed25519}[c]()
        res.append(Resolution(c, "classical", "ok", c, "pyca/cryptography (OpenSSL)"))
    for s in cfg["symmetric"]:
        tag = int(s.rsplit("T", 1)[1])
        algs[s] = HmacSha256(tag)
        res.append(Resolution(s, "symmetric", "ok", s, "pyca/cryptography (OpenSSL)"))

    for h in cfg["hybrid"]:
        missing = [p for p in h["parts"] if p not in algs]
        if missing:
            res.append(Resolution(h["label"], "hybrid", "unavailable", "", f"component(s) unavailable: {missing}"))
            continue
        a_cls = type(algs[h["parts"][0]])
        a = a_cls() if a_cls in (EcdsaP256, Ed25519) else algs[h["parts"][0]]
        b_src = algs[h["parts"][1]]
        b = OqsSig(oqs, b_src.name, b_src.impl_name)
        algs[h["label"]] = Hybrid(h["label"], a, b)
        res.append(Resolution(h["label"], "hybrid", "ok", algs[h["label"]].impl_name, "concatenated, AND-verify"))

    return list(algs.values()), kems, res

