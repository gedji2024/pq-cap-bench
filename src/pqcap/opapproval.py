"""F6: pre-committed operator approvals (hash chain) vs per-command OP signature tokens.

Chain variant: at commissioning OP signs a commitment to the top of a hash chain bound to (device, action):
top = H^n(s). Approval k reveals x_k = H^(n-k)(s) (16 or 32 B, the chain element length); the device checks
H(x_k) against its anchor and moves the anchor. One reveal = one approval, so a "disable sensor" command carries
the crisis command plus one reveal. Token variant: the command carries one OP signature over (D, handle, ctr)
(D2). Formal model: formal/opchain.spthy (disable_needs_OP_chain, one_reveal_one_approval).

Frames and per-device Class A latency for the disable message (command + approval) at every LoRa DR, and the
one-off commissioning message (commitment + its OP signature).
"""

from __future__ import annotations

import pandas as pd

from . import delivery as dl


def approval_rows(chans, command_bytes: int, approvals: dict[str, int], commit_fields_bytes: int,
                  commit_signers: dict[str, int], uplink_s: float, link_cost) -> tuple[pd.DataFrame, pd.DataFrame]:
    """approvals: label -> approval bytes carried with each disable command (chain reveal or signature).
    commit_signers: OP signature algorithm -> signature bytes for the one-off chain commitment."""
    per_cmd, commit = [], []
    for ch in chans:
        if ch.phy is None:
            continue
        for label, nb in approvals.items():
            lc = link_cost(command_bytes + nb, ch)
            t = dl.time_to_deliver_s(lc["frames"], uplink_s, 1.0, lc["last_frame_toa_s"])
            per_cmd.append({"approval": label, "approval_bytes": nb, "message_bytes": command_bytes + nb,
                            "region": ch.region, "dr": ch.dr, "frames": lc["frames"], "airtime_s": lc["airtime_s"],
                            "latency_worst_s": t["ttd_worst_s"], "latency_expected_s": t["ttd_expected_s"]})
        for alg, sb in commit_signers.items():
            lc = link_cost(commit_fields_bytes + sb, ch)
            commit.append({"commit_signer": alg, "commit_bytes": commit_fields_bytes + sb, "region": ch.region,
                           "dr": ch.dr, "frames": lc["frames"], "airtime_s": lc["airtime_s"]})
    return pd.DataFrame(per_cmd), pd.DataFrame(commit)
