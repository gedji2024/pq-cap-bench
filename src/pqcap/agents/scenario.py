"""E1 scenarios: one per G4 storm cluster of the F5 pre-registered events (real USGS replay, NWS categories).

Rule (pre-registered in experiments/agents/PREREG.md):
- representative event of a cluster = the event whose peak exceeds its gauge's NWS minor stage by the most
  (ties: earlier peak, then USGS id);
- t0 = first minute the representative gauge reaches its NWS action stage, plus `lead_min`;
- the fleet = one sensor on every gauge of the cluster whose event window covers t0 (the primary gauge first);
- each gauge shows the last `history_h` hours before t0 at `step_min` resolution; the rest of its event after t0
  is kept for the hydrological-impact replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from .. import harm, nws


@dataclass
class GaugeView:
    usgs: str
    lid: str
    name: str
    categories_ft: dict
    readings: list            # [(iso time, stage ft)] oldest first, last one at t0
    alert_cm: int
    band_cm: tuple
    levels_cm: list
    stage_after_cm: np.ndarray = field(repr=False)   # 1-min grid from t0 to the end of the event window

    @property
    def stage_ft(self) -> float:
        return self.readings[-1][1]

    def category(self) -> str:
        """NWS category of the current stage (the highest one reached), or 'below action'."""
        out = "below action"
        for k in nws.CATEGORIES:
            if self.categories_ft.get(k) is not None and self.stage_ft >= self.categories_ft[k]:
                out = k
        return out


@dataclass
class Scenario:
    id: str
    cluster: int
    t0: pd.Timestamp
    primary: str
    gauges: dict              # usgs -> GaugeView, primary first
    events: list              # event names in the cluster


def _readings(s_start: pd.Timestamp, stage_cm: np.ndarray, t0_min: int, history_h: float, step_min: int,
              ft_to_cm: float) -> list:
    lo = max(0, t0_min - int(history_h * 60))
    mins = range(t0_min - ((t0_min - lo) // step_min) * step_min, t0_min + 1, step_min)
    return [((s_start + pd.Timedelta(minutes=m)).isoformat(), round(float(stage_cm[m]) / ft_to_cm, 2)) for m in mins]


def build(hcfg: dict, root: Path, lead_min: int = 60, history_h: float = 6, step_min: int = 15) -> list[Scenario]:
    ft = hcfg["series"]["ft_to_cm"]
    evs = harm.event_list(hcfg, root)
    info = {}
    for e in evs:
        stage, s = harm.event_stage(e, hcfg, root)
        cats = nws.load(root / hcfg["nws"]["dir"], e["usgs"], hcfg["nws"]["datum_tol_ft"])
        th = harm.nws_thresholds(cats, ft)
        info[e["name"]] = {"ev": e, "stage": stage, "start": s.index[0], "cats": cats, "th": th,
                           "peak_time": s.idxmax(), "excess_ft": float(s.max()) / ft - cats["minor"]}
    clusters = harm.storm_clusters({n: i["peak_time"] for n, i in info.items()}, hcfg["statistics"]["cluster_window_h"])
    out = []
    for cid in sorted(set(clusters.values())):
        names = [n for n in info if clusters[n] == cid]
        rep = sorted(names, key=lambda n: (-info[n]["excess_ft"], info[n]["peak_time"], info[n]["ev"]["usgs"]))[0]
        r = info[rep]
        first = int(np.argmax(r["stage"] >= r["th"]["alert_cm"]))
        t0 = r["start"] + pd.Timedelta(minutes=first + lead_min)
        gauges = {}
        for n in [rep] + sorted((x for x in names if x != rep), key=lambda x: info[x]["ev"]["usgs"]):
            i = info[n]
            m = int((t0 - i["start"]).total_seconds() // 60)
            if not 0 <= m < i["stage"].size or i["ev"]["usgs"] in gauges:
                continue
            c = i["cats"]
            gauges[i["ev"]["usgs"]] = GaugeView(
                i["ev"]["usgs"], c["lid"], c["name"], {k: c[k] for k in nws.CATEGORIES},
                _readings(i["start"], i["stage"], m, history_h, step_min, ft), i["th"]["alert_cm"],
                tuple(i["th"]["band_cm"]), list(i["th"]["levels_cm"]), i["stage"][m:])
        out.append(Scenario(f"SC{cid:02d}", cid, t0, r["ev"]["usgs"], gauges, names))
    return out
