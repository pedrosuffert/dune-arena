"""Definitive multi-seed analysis: mean±std per model, offline-vs-in-network
fidelity, pairwise Wilcoxon (tie test), collisions, partition stability.

Reads data/output/multiseed_{offline,innetwork}.csv (written by multiseed.py).
Run:  uv run python treeshap/analyze_multiseed.py | tee data/output/multiseed_summary.txt
"""
from itertools import combinations

import pandas as pd
from scipy.stats import wilcoxon

import paths

MODELS = ["rf", "xgboost", "lightgbm", "catboost"]
inn = pd.read_csv(paths.OUTPUT / "multiseed_innetwork.csv")
off = pd.read_csv(paths.OUTPUT / "multiseed_offline.csv")
fair = off[off.regime == "fair"]
orig = off[off.regime == "original"]

print(f"seeds: in-network n={inn.seed.nunique()}, offline n={off.seed.nunique()}")

print("\n=== OFFLINE macro-F1 (fair = propagation fix), mean ± std ===")
for m in MODELS:
    s = fair[fair.model == m]["macro"]
    print(f"  {m:9}: {s.mean():.2f} ± {s.std():.2f}")

print("\n=== OFFLINE macro-F1 (original DUNE regime), mean ± std ===")
for m in MODELS:
    s = orig[orig.model == m]["macro"]
    print(f"  {m:9}: {s.mean():.2f} ± {s.std():.2f}")

print("\n=== IN-NETWORK macro-F1 (line topology, fair regime), mean ± std ===")
for m in MODELS:
    s = inn[inn.model == m]["macro"] * 100
    print(f"  {m:9}: {s.mean():.2f} ± {s.std():.2f}   (min {s.min():.2f}, max {s.max():.2f})")
means = [100 * inn[inn.model == m]["macro"].mean() for m in MODELS]
print(f"  spread across models: {max(means) - min(means):.2f} p.p.")

print("\n=== FIDELITY: offline(fair) vs in-network, paired per seed ===")
for m in MODELS:
    o = fair[fair.model == m].set_index("seed")["macro"]
    i = inn[inn.model == m].set_index("seed")["macro"] * 100
    d = (o - i).dropna()
    print(f"  {m:9}: offline {o.mean():.2f}  in-net {i.mean():.2f}  gap {d.mean():+.2f} ± {d.std():.2f} p.p.")

def rank_biserial(d):
    """Matched-pairs rank-biserial correlation (effect size for the Wilcoxon).
    +1 = first always higher, 0 = symmetric."""
    d = pd.Series(d).dropna()
    d = d[d != 0]
    if d.empty:
        return 0.0
    r = d.abs().rank()
    return float((r[d > 0].sum() - r[d < 0].sum()) / r.sum())


def holm(pairs_p):
    """Holm step-down adjusted p-values: {pair: p_adj}."""
    m = len(pairs_p)
    s = sorted(pairs_p.items(), key=lambda kv: kv[1])
    adj, run = {}, 0.0
    for i, (k, p) in enumerate(s):
        run = max(run, min(1.0, (m - i) * p))
        adj[k] = run
    return adj


print("\n=== TIE TEST: pairwise Wilcoxon on in-network macro (paired by seed) ===")
piv = inn.pivot(index="seed", columns="model", values="macro")
raw_p = {}
for a, b in combinations(MODELS, 2):
    try:
        st, p = wilcoxon(piv[a], piv[b])
        raw_p[(a, b)] = p
    except Exception as e:
        print(f"  {a} vs {b}: {e}")
adj_p = holm(raw_p)
for (a, b), p in raw_p.items():
    rb = rank_biserial(piv[a] - piv[b])
    pa = adj_p[(a, b)]
    sig = "  *SIGNIFICANT (Holm)*" if pa <= 0.05 else "  (n.s. after Holm)"
    print(f"  {a} vs {b}: median diff {100 * (piv[a] - piv[b]).median():+.2f} p.p., "
          f"p={p:.3f}, p_holm={pa:.3f}, rank-biserial={rb:+.2f}{sig}")

print("\n=== FIDELITY significance: offline(fair) vs in-network per model (Wilcoxon) ===")
for m in MODELS:
    o = fair[fair.model == m].set_index("seed")["macro"]
    i = inn[inn.model == m].set_index("seed")["macro"] * 100
    d = (o - i).dropna()
    try:
        st, p = wilcoxon(d)
        rb = rank_biserial(d)
        print(f"  {m:9}: gap {d.mean():+.2f} p.p., p={p:.3f}, rank-biserial={rb:+.2f}")
    except Exception as e:
        print(f"  {m:9}: {e}")

print("\n=== TIE TEST: pairwise Wilcoxon on offline fair macro ===")
piv_o = fair.pivot(index="seed", columns="model", values="macro")
for a, b in combinations(MODELS, 2):
    try:
        st, p = wilcoxon(piv_o[a], piv_o[b])
        sig = "  *SIGNIFICANT*" if p <= 0.05 else "  (n.s.)"
        print(f"  {a} vs {b}: median diff {(piv_o[a] - piv_o[b]).median():+.2f} p.p., p={p:.3f}{sig}")
    except Exception as e:
        print(f"  {a} vs {b}: {e}")

print("\n=== COLLISIONS (per-flow register state), mean per model ===")
for m in MODELS:
    print(f"  {m:9}: {inn[inn.model == m]['collisions'].mean():.0f}")

print("\n=== TCAM (offline fair), mean per model ===")
for m in MODELS:
    print(f"  {m:9}: {fair[fair.model == m]['tcam'].mean():.2f}")

def canon(p):
    """Order-independent partition key: cluster numbering is a deploy detail,
    the grouping is what the stability claim is about."""
    return " ".join(sorted(p.split(" ")))


print("\n=== PARTITION stability (fair): distinct class GROUPINGS per model over seeds ===")
fair = fair.assign(grouping=fair["partition"].map(canon))
for m in MODELS:
    parts = fair[fair.model == m]["grouping"]
    vc = parts.value_counts()
    print(f"  {m:9}: {len(vc)} distinct; top: {vc.index[0]} ({vc.iloc[0]}/{len(parts)})")

print("\n=== ddos+dos co-location rate (fair), per model ===")
def together(p):
    blocks = [set(b.strip("{}").split(",")) for b in p.split(" ")]
    return any({"ddos", "dos"} <= b for b in blocks)
for m in MODELS:
    parts = fair[fair.model == m]["partition"]
    print(f"  {m:9}: {100 * parts.apply(together).mean():.0f}% of seeds")

print("\n=== IDENTICAL-GROUPING coincidences across models (fair), per seed ===")
per_seed = fair.pivot(index="seed", columns="model", values="grouping")
same_all = (per_seed.nunique(axis=1) == 1).mean()
print(f"  all four identical: {100 * same_all:.0f}% of seeds")
