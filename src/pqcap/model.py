"""Combine measured sizes with the radio/token model and write results/model_*.csv."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from . import delivery as dl
from . import s6 as s6m
from .config import REPO_ROOT as _REPO_ROOT
from .config import load_yaml
from .radio import LoraPhy, MacOverhead, duty_cycle_off_time_s, fragment, frames_airtime_s, time_on_air_s
from .token import SCHEME_DESC, TokenModel, epoch_message_bytes

RX1_DELAY_S = 1.0  # [RP002] Sec. 2.3 RECEIVE_DELAY1 (recommended default)


@dataclass(frozen=True)
class Channel:
    region: str
    dr: int
    phy: LoraPhy | None      # None => NB-IoT (no LoRa ToA)
    max_app: int
    duty: float | None
    mac: MacOverhead | None  # LoRaWAN framing around FRMPayload (None for NB-IoT)


def commissioning_threshold_cm(actions_cfg: dict, root) -> int:
    """F3: write-once maximum alert threshold (cm) = the configured NWS category of the configured gauge (F4 data);
    0 (no bound) when the profile defines none."""
    c = (actions_cfg.get("commissioning") or {}).get("max_alert_threshold_nws")
    if not c:
        return 0
    from . import nws  # noqa: PLC0415
    cats = nws.load(root / "data/nws", c["usgs"], 0.5)
    return int(round(cats[c["category"]] * 30.48))


def channels(radio: dict, model: dict) -> list[Channel]:
    p, ov = radio["phy"], radio["lorawan_overhead"]
    mac = MacOverhead(ov["mhdr"], ov["fhdr_min"], ov["fport"], ov["mic"], ov.get("fopts_bytes", 0))
    variant = {"not_repeater_compatible": "norep", "repeater_compatible": "rep"}[radio["payload_table_variant"]]
    out = []
    for region, r in radio["regions"].items():
        duty = model["eu868_duty_cycle"] if r["duty_cycle"] == "from_model_config" else r["duty_cycle"]
        for dr, d in r["downlink_drs"].items():
            phy = LoraPhy(sf=d["sf"], bw_hz=d["bw_khz"] * 1e3, cr=p["coding_rate"],
                          preamble=p["preamble_symbols"], explicit_header=p["explicit_header"],
                          crc_on=p["crc_on_downlink"], ldro_threshold_ms=p["ldro_symbol_time_threshold_ms"])
            out.append(Channel(region, int(dr), phy, d[variant]["N"] - mac.fopts, duty, mac))
    out.append(Channel("NB-IoT", 0, None, model["nbiot_max_payload_bytes"], None, None))
    return out


def measured_sizes(results: Path, stat: str) -> tuple[dict, dict]:
    col = {"min": "sig_min", "median": "sig_median", "max": "sig_max"}[stat]
    s = pd.read_csv(results / "sizes.csv")
    sig = {r.algorithm: int(math.ceil(getattr(r, col))) for r in s.itertuples()}
    k = pd.read_csv(results / "kem_sizes.csv")
    kem = {r.algorithm: int(r.ct_bytes) for r in k.itertuples()}
    return sig, kem


def scheme_rows(model: dict, sig: dict) -> list[dict]:
    """(scheme, algorithm, per-command authenticator bytes) for every available combination."""
    rows = []
    for a in model["s1_algorithms"]:
        if a in sig:
            rows.append({"scheme": "S1", "algorithm": a, "auth_bytes": sig[a]})
    h = model["hmac_label"]
    if h in sig:
        rows.append({"scheme": "S2", "algorithm": f"{model['s2_cert_signer']}+KEM/{h}", "auth_bytes": sig[h]})
        rows.append({"scheme": "S4", "algorithm": h, "auth_bytes": sig[h]})
    if model["hybrid_label"] in sig:
        rows.append({"scheme": "S3", "algorithm": model["hybrid_label"], "auth_bytes": sig[model["hybrid_label"]]})
    if model["classical_label"] in sig:
        rows.append({"scheme": "S5", "algorithm": model["classical_label"], "auth_bytes": sig[model["classical_label"]]})
    for r in rows:
        r["scheme_desc"] = SCHEME_DESC[r["scheme"]]
    return rows


def link_cost(nbytes: int, ch: Channel, frag_header: int) -> dict:
    fr = fragment(nbytes, ch.max_app, frag_header)
    if ch.phy is None:
        return {"frames": fr.frames, "airtime_s": float("nan"), "last_frame_toa_s": float("nan"),
                "duty_off_time_s": float("nan")}
    air = frames_airtime_s(fr, ch.phy, ch.mac)
    return {"frames": fr.frames, "airtime_s": air,
            "last_frame_toa_s": time_on_air_s(ch.mac.phy_payload(fr.app_payloads[-1]), ch.phy),
            "duty_off_time_s": duty_cycle_off_time_s(air, ch.duty)}


def build(token_cfg: dict, radio: dict, model: dict, sig: dict, kem: dict) -> dict[str, pd.DataFrame]:
    tm = TokenModel.from_config(token_cfg)
    depths = token_cfg["delegation"]["depths"]
    chans = channels(radio, model)
    fh, U = model["fragment_header_bytes"], model["uplink_interval_s"]
    schemes = scheme_rows(model, sig)

    tokens, deliv, cap = [], [], []
    for s in schemes:
        for d in depths:
            size = tm.size(s["auth_bytes"], d)
            tokens.append({**s, "depth": d, "token_bytes": size, "auth_overhead_bytes": tm.auth_overhead(s["auth_bytes"], d)})
            for ch in chans:
                lc = link_cost(size, ch, fh)
                row = {**s, "depth": d, "token_bytes": size, "region": ch.region, "dr": ch.dr,
                       "max_app_payload": ch.max_app, "duty_cycle": ch.duty, **lc}
                if ch.phy is not None:
                    row.update(dl.time_to_deliver_s(lc["frames"], U, RX1_DELAY_S, lc["last_frame_toa_s"]))
                    for W in model["windows_min"]:
                        for N in model["devices_per_gateway"]:
                            g = dl.commands_per_gateway(N, W * 60, U, lc["frames"], lc["airtime_s"], ch.duty)
                            cap.append({"scheme": s["scheme"], "algorithm": s["algorithm"], "depth": d,
                                        "region": ch.region, "dr": ch.dr, "window_min": W, "devices": N,
                                        "frames": lc["frames"],
                                        "cmds_per_device": dl.commands_per_device(W * 60, U, lc["frames"]),
                                        **g, "all_devices_get_one": g["cmds_gateway"] >= N
                                        and dl.commands_per_device(W * 60, U, lc["frames"]) >= 1})
                deliv.append(row)

    amort = s2_amortization(tm, chans, model, sig, kem)
    out = {"model_tokens": pd.DataFrame(tokens), "model_delivery": pd.DataFrame(deliv),
           "model_capacity": pd.DataFrame(cap), "model_s2_amortization": amort}
    if "s6" in model:
        lc = lambda n, ch: link_cost(n, ch, fh)  # noqa: E731
        Ns = model["devices_per_gateway"]
        out["model_s6_calm"] = s6m.calm_feasibility(chans, model["s6"], sig, U, Ns, lc)
        out["model_s6_crisis"] = s6m.crisis_capacity(chans, model["s6"], U, Ns, lc, token_body=tm.body)
        out["model_s6_compare"] = s6m.compare(out["model_s6_crisis"], out["model_capacity"],
                                              out["model_delivery"], {**model["s6"], "uplink_interval_s": U})
    return out


def s2_amortization(tm: TokenModel, chans, model, sig, kem) -> pd.DataFrame:
    fh, U = model["fragment_header_bytes"], model["uplink_interval_s"]
    h, signer = model["hmac_label"], model["s2_cert_signer"]
    rows = []
    if h not in sig or signer not in sig:
        return pd.DataFrame(rows)
    cmd_bytes = tm.size(sig[h], 0)
    for k_name in model["s2_kem"]:
        if k_name not in kem:
            continue
        ep_bytes = epoch_message_bytes(model["s2_epoch_cert_fields"], sig[signer], kem[k_name])
        for ch in chans:
            if ch.phy is None:
                continue
            ep, cmd = link_cost(ep_bytes, ch, fh), link_cost(cmd_bytes, ch, fh)
            for T in model["epoch_hours"]:
                k_max = (dl.downlink_opportunities(T * 3600, U) - ep["frames"]) // cmd["frames"]
                if k_max < 1:  # epoch message alone exhausts the epoch's downlink opportunities
                    rows.append({"kem": k_name, "cert_signer": signer, "region": ch.region, "dr": ch.dr,
                                 "epoch_hours": T, "cmds_per_epoch": 0, "is_class_a_max": True,
                                 "is_configured_point": False, "feasible": False,
                                 "epoch_bytes": ep_bytes, "epoch_frames": ep["frames"],
                                 "epoch_airtime_s": ep["airtime_s"], "cmd_bytes": cmd_bytes,
                                 "cmd_frames": cmd["frames"]})
                    continue
                for k in sorted(set(model["s2_commands_per_epoch"] + [max(k_max, 0)])):
                    if k < 1 or k > k_max:
                        continue
                    s2_air = cmd["airtime_s"] + ep["airtime_s"] / k
                    s2_b = cmd_bytes + ep_bytes / k
                    rows.append({"kem": k_name, "cert_signer": signer, "region": ch.region, "dr": ch.dr,
                                 "epoch_hours": T, "cmds_per_epoch": k, "is_class_a_max": k == k_max,
                                 "is_configured_point": k in model["s2_commands_per_epoch"],
                                 "epoch_bytes": ep_bytes, "epoch_frames": ep["frames"],
                                 "epoch_airtime_s": ep["airtime_s"], "cmd_bytes": cmd_bytes,
                                 "cmd_frames": cmd["frames"], "s4_airtime_per_cmd_s": cmd["airtime_s"],
                                 "s2_airtime_per_cmd_s": s2_air, "ratio_airtime_s2_s4": s2_air / cmd["airtime_s"],
                                 "s4_bytes_per_cmd": cmd_bytes, "s2_bytes_per_cmd": s2_b,
                                 "ratio_bytes_s2_s4": s2_b / cmd_bytes, "feasible": True})
    return pd.DataFrame(rows)


def crc_sensitivity(base: dict, alt: dict, model: dict, alt_crc: bool) -> pd.DataFrame:
    """Depth-0 LoRa rows: primary setting vs the alternative downlink-CRC setting."""
    keys = ["scheme", "algorithm", "depth", "region", "dr"]
    cols = ["frames", "airtime_s", "ttd_worst_s"]
    a = base["model_delivery"]
    b = alt["model_delivery"]
    a, b = a[(a.depth == 0) & (a.region != "NB-IoT")], b[(b.depth == 0) & (b.region != "NB-IoT")]
    m = a[keys + ["token_bytes"] + cols].merge(b[keys + cols], on=keys, suffixes=("", "_alt"))
    k1 = model["kill_criteria"]["K1"]
    ca, cb = base["model_capacity"], alt["model_capacity"]
    sel = lambda c: c[(c.depth == 0) & (c.window_min == k1["window_min"]) & (c.devices == k1["devices"])][keys + ["cmds_gateway"]]  # noqa: E731
    m = m.merge(sel(ca), on=keys).merge(sel(cb), on=keys, suffixes=("", "_alt"))
    m["airtime_delta_rel"] = m.airtime_s_alt / m.airtime_s - 1
    m["alt_crc_on_downlink"] = alt_crc
    return m


def run(config: Path, results: Path) -> dict[str, pd.DataFrame]:
    model = load_yaml(config / "model.yaml")
    radio = load_yaml(config / "radio.yaml")
    token = load_yaml(config / "token.yaml")
    sig, kem = measured_sizes(results, model["signature_size_statistic"])
    out = build(token, radio, model, sig, kem)
    alt_crc = radio["phy"]["sensitivity_crc_on_downlink"]
    radio_alt = {**radio, "phy": {**radio["phy"], "crc_on_downlink": alt_crc}}
    out_alt = build(token, radio_alt, model, sig, kem)
    out["model_sensitivity_crc"] = crc_sensitivity(out, out_alt, model, alt_crc)
    for name, df in out.items():
        df.to_csv(results / f"{name}.csv", index=False)
    harm_p, actions_p = config / "harm.yaml", config / "actions.yaml"
    if harm_p.exists() and actions_p.exists():
        from . import harm  # noqa: PLC0415
        from .config import REPO_ROOT  # noqa: PLC0415
        hcfg = load_yaml(harm_p)
        series = REPO_ROOT / hcfg["series"]["file"]
        if series.exists():
            hd, he, hm = harm.run(hcfg, load_yaml(actions_p), REPO_ROOT)
            hd.to_csv(results / "model_harm.csv", index=False)
            st = hcfg.get("statistics", {"bootstrap": 10000, "seed": 0})
            harm.summarize_events(hd, st["bootstrap"], st["seed"]).to_csv(results / "model_harm_summary.csv", index=False)
            he.to_csv(results / "model_harm_events.csv", index=False)
            if not he.empty:
                harm.delay_distribution(he, hcfg["harm"]["delay_tolerance_min"], st["bootstrap"], st["seed"]).to_csv(
                    results / "model_harm_delays.csv", index=False)
            for em in hm["events"]:
                srcs = []
                for f in em["files"]:
                    mp = REPO_ROOT / (f.removesuffix(".gz").removesuffix(".json") + ".meta.json")
                    srcs.append(json.loads(mp.read_text()) if mp.exists() else {})
                em["source"] = srcs
            (results / "harm_meta.json").write_text(json.dumps(hm, indent=2, default=str))
    if (config / "devices").is_dir() and (config / "policies.yaml").exists():
        from . import devices as devm  # noqa: PLC0415
        cdf, ck5, ck6 = devm.run(config)
        cdf.to_csv(results / "catalogue_blast.csv", index=False)
        ck5.to_csv(results / "catalogue_k5_ranges.csv", index=False)
        ck6.to_csv(results / "catalogue_k6_ranges.csv", index=False)
        thr_ = load_yaml(config / "threat.yaml")
        if "s4e_key_scope" in thr_:
            acf = load_yaml(config / "actions.yaml")
            cs = acf.get("count_state", {"alert_active": True, "battery_above_floor": True})
            ks = devm.c4_key_scope(devm.load_catalogue(config / "devices"), load_yaml(config / "policies.yaml"), thr_,
                                   acf["invariants"], {"alert_active": cs["alert_active"],
                                                       "battery_below_floor": not cs["battery_above_floor"]})
            ks.to_csv(results / "f1_c4_key_scope.csv", index=False)
            devm.c4_k6(ks).to_csv(results / "f1_c4_k6.csv", index=False)
        if "d6" in model:
            from . import gateway as gw  # noqa: PLC0415
            devs_ = devm.load_catalogue(config / "devices")
            pols = load_yaml(config / "policies.yaml")
            lc6 = lambda n, ch: link_cost(n, ch, model["fragment_header_bytes"])  # noqa: E731
            gw.filter_savings(devs_, pols, channels(load_yaml(config / "radio.yaml"), model), model["uplink_interval_s"],
                              model["d6"]["devices_per_gateway"], lc6, model["d6"]["flood_mixes"],
                              tuple(model["d6"].get("filter_points", ["appskey_upper_bound"]))).to_csv(
                results / "d6_gateway_filter.csv", index=False)
            acfg_ = load_yaml(config / "actions.yaml")
            c_ = acfg_.get("count_state", {"alert_active": True, "battery_above_floor": True})
            gw.forging_power(devs_, pols, load_yaml(config / "threat.yaml"), acfg_["invariants"],
                             {"alert_active": c_["alert_active"], "battery_below_floor": not c_["battery_above_floor"]}
                             ).to_csv(results / "d6_forging_power.csv", index=False)
    from .config import REPO_ROOT as _root  # noqa: PLC0415
    if (_root / "formal/proofs").is_dir():
        from . import formal  # noqa: PLC0415
        formal.results(_root / "formal/proofs").to_csv(results / "formal_lemmas.csv", index=False)
    if (config / "mcu.yaml").exists():
        from . import pqm4  # noqa: PLC0415
        from .config import REPO_ROOT  # noqa: PLC0415
        if (REPO_ROOT / "data/pqm4/SOURCE.json").exists():
            mc = pqm4.verification_cost(config, REPO_ROOT)
            for V in model.get("revocation", {}).get("validity_hours", []):  # one verify per renewal
                mc[f"verify_ms_per_day_V{V}h"] = mc.verify_ms_avg * 24 / V
            mc.to_csv(results / "mcu_verify_cost.csv", index=False)
    from .kill import evaluate  # noqa: PLC0415
    k = evaluate(out, model)
    k["K1_crc_sensitivity"] = evaluate(out_alt, model)["K1"]
    actions = config / "actions.yaml"
    if actions.exists() and "s6" in model:
        from . import blast  # noqa: PLC0415
        from . import envelope as ev  # noqa: PLC0415
        acfg = load_yaml(actions)
        cat, env, inv = ev.catalogue_from_config(acfg), ev.envelope_from_config(acfg), ev.invariants_from_config(acfg)
        ev.encode_envelope(env)  # scenario must fit the 112-B envelope (64-B bounds, 32-B invariants)
        ref = blast.reference_state_name(acfg)
        tag_len = model["s6"]["tag_bytes"][0]
        br = blast.blast_s4_s6(cat, env, inv, tag_len)
        br.to_csv(results / "model_blast_radius.csv", index=False)
        k["K5"] = blast.k5(br, ref)
        threat_p = config / "threat.yaml"
        if threat_p.exists():
            fw = ev.firmware_policy_from_config(acfg)
            bc = blast.blast_compromise(cat, env, fw, inv, load_yaml(threat_p), tag_len,
                                        commissioning_threshold_cm(acfg, _REPO_ROOT))
            bc.to_csv(results / "model_blast_compromise.csv", index=False)
            k["K5"]["matrix_labels"] = {c: f"{v['label']} [scope: {v['scope']}]"
                                         for c, v in load_yaml(threat_p)["compromises"].items()}
            k["K5"]["matrix"] = (bc[bc.state == ref].groupby(["compromise", "scheme"], sort=False).accepted.sum()
                                 .unstack().reset_index().to_dict("records"))
            env_b = {"S4-E": ev.ENVELOPE_BYTES + sig[model["s4e_envelope_mac"]],
                     "S6": ev.ENVELOPE_BYTES + sig[model["s6"]["signers"][0]]}
            k["K6"] = blast.k6(bc, ref, env_b)
            d2 = bc[bc.compromise.isin(["C1", "C1+C3", "C1+C3+OP"])].groupby(
                ["state", "compromise", "scheme"], sort=False).accepted.sum().unstack().reset_index()
            d2.to_csv(results / "d2_blast_s6f.csv", index=False)
            # OP approval token = one signature over the command; size per measured algorithm, frames at each LoRa DR
            tok = []
            for alg in model.get("d2_op_token_algorithms", []):
                if alg in sig:
                    for ch in channels(radio, model):
                        if ch.phy is not None:
                            lcx = link_cost(sig[alg], ch, model["fragment_header_bytes"])
                            tok.append({"op_token_alg": alg, "token_bytes": sig[alg], "region": ch.region, "dr": ch.dr,
                                        "frames": lcx["frames"], "airtime_s": lcx["airtime_s"]})
            pd.DataFrame(tok).to_csv(results / "d2_op_token_cost.csv", index=False)
            if "revocation" in model:
                from . import revocation as rv  # noqa: PLC0415
                chans = channels(radio, model)
                lc = lambda n, ch: link_cost(n, ch, model["fragment_header_bytes"])  # noqa: E731
                U = model["uplink_interval_s"]
                env_r = {**env_b, "S6-R": env_b["S6"] + ev.REV_COMMIT_BYTES}   # D1: + H(r_rev) in the envelope
                reveal = {"S6-R": [ev.REVOCATION.size + b for b in model["revocation"]["s6r_reveal_bytes"]]}
                rv.exposure(chans, env_r, model["revocation"], U, lc, reveal).to_csv(
                    results / "model_revocation_exposure.csv", index=False)
                rv.renewal_cost(chans, env_r, model["revocation"], U, lc).to_csv(results / "model_renewal_cost.csv",
                                                                                index=False)
    (results / "kill_criteria.json").write_text(json.dumps(k, indent=2, default=str))
    return out
