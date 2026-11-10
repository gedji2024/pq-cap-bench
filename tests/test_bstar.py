"""B* ranges quoted in the manuscript (formal.tex, Corollary cor:bstar) are reproduced by theory/bstar.py."""
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('bstar', Path(__file__).resolve().parents[1] / 'theory/bstar.py')
bstar = importlib.util.module_from_spec(spec); spec.loader.exec_module(bstar)

def test_ranges_match_manuscript():
    want = {40: (23.0, 32.4, 27.8), 60: (66.3, 84.4, 79.8), 80: (109.7, 136.4, 131.8)}
    for soc0, (lo, hi, lo4) in want.items():
        r = bstar.ranges(soc0)
        assert (r['bstar_min'], r['bstar_max'], r['bstar_min_j4']) == (lo, hi, lo4)
        assert r['tau_j5_from'] == 7200 - bstar.I_max
