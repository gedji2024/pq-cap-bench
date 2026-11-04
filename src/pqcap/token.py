"""Capability-token and per-scheme wire sizes.

All authenticator sizes are passed in from measurements (results/sizes.csv,
results/kem_sizes.csv); this module only does the arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass

SCHEMES = ("S1", "S2", "S3", "S4", "S5")
SCHEME_DESC = {
    "S1": "per-command PQ signature",
    "S2": "PQ-signed epoch cert + KEM, per-command HMAC",
    "S3": "hybrid ECDSA-P256+ML-DSA-44 per command",
    "S4": "symmetric HMAC only (pre-shared key)",
    "S5": "classical ECDSA-P256 per command",
}


@dataclass(frozen=True)
class TokenModel:
    header: int
    constraints: int
    hop_constraints: int
    hop_key_id: int

    @classmethod
    def from_config(cls, cfg: dict) -> "TokenModel":
        return cls(
            header=sum(cfg["header"].values()),
            constraints=sum(cfg["constraints"].values()),
            hop_constraints=cfg["delegation"]["constraints_per_hop"],
            hop_key_id=cfg["delegation"]["key_id"],
        )

    @property
    def body(self) -> int:
        return self.header + self.constraints

    def size(self, auth_bytes: int, depth: int) -> int:
        """Token = header + constraints + root authenticator
        + depth x (hop constraints + key id + hop authenticator).
        Each hop is authenticated with the same mechanism as the root."""
        if depth < 0:
            raise ValueError("delegation depth must be >= 0")
        if auth_bytes < 0:
            raise ValueError("authenticator size must be >= 0")
        return self.body + auth_bytes + depth * (self.hop_constraints + self.hop_key_id + auth_bytes)

    def auth_overhead(self, auth_bytes: int, depth: int) -> int:
        """Bytes beyond the unauthenticated root body."""
        return self.size(auth_bytes, depth) - self.body


def epoch_message_bytes(cert_fields: dict, cert_sig_bytes: int, kem_ct_bytes: int) -> int:
    """S2 epoch message = cert body + PQ signature over it + KEM ciphertext
    carrying the per-epoch symmetric key."""
    return sum(cert_fields.values()) + cert_sig_bytes + kem_ct_bytes
