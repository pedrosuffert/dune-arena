"""Recover per-run flow-weighted confusion matrices from the testbed archives.

For every campaign archive `testbed/experiment_<N>.tar.gz` (matched to its
(seed, model) row in multiseed_innetwork.csv by the exact Macro value, like
extract_per_run_reports.py), read the final-egress capture (pcaps/combined.csv),
join it with the ground truth and weight each packet by 1/packet_counts, the
same flow weighting calculate_score.py uses.

The data plane numbers classes by cluster deploy order, which varies per run,
so the id -> class map is derived per run: each true class takes the id holding
most of its flow-weighted mass (bijective, or the run is skipped). Every
diagonal is validated against the archived per-class recall
(per_class_innetwork.csv) within 0.005. Predictions with id 0 are kept as the
"nenhuma" column: packets that left the chain without any verdict.

Output: data/output/confusion_per_seed.csv
        (model, seed, true, pred, frac)   rows sum to 1 per (model, seed, true)
"""
import io
import re
import tarfile

import pandas as pd

import paths

TESTBED = paths.ROOT / "testbed"
TYPES = ["ddos", "dos", "normal", "scanning", "password", "xss", "injection"]

inn = pd.read_csv(paths.OUTPUT / "multiseed_innetwork.csv")
inn["macro_r"] = inn["macro"].round(9)
per_class = pd.read_csv(paths.OUTPUT / "per_class_innetwork.csv")
gt = pd.read_csv(paths.OUTPUT / "ToN_IoT_Flow_PktCounts.csv").drop(columns=["Unnamed: 0"], errors="ignore")

rows, skipped = [], []
for tar_path in sorted(TESTBED.glob("experiment_*.tar.gz"),
                       key=lambda p: int(re.search(r"_(\d+)", p.stem.replace(".tar", "")).group(1))):
    with tarfile.open(tar_path) as tf:
        member = next((m for m in tf.getmembers() if re.match(r"results_.*\.txt$", m.name)), None)
        if member is None:
            skipped.append((tar_path.name, "no results txt"))
            continue
        txt = tf.extractfile(member).read().decode()
        mm = re.search(r"Macro=([0-9.]+)", txt)
        if not mm:
            skipped.append((tar_path.name, "no Macro"))
            continue
        hit = inn[inn["macro_r"] == round(float(mm.group(1)), 9)]
        if len(hit) != 1:
            skipped.append((tar_path.name, f"macro match x{len(hit)} (smoke or dup)"))
            continue
        seed, model = int(hit.iloc[0]["seed"]), hit.iloc[0]["model"]
        combined = next((m for m in tf.getmembers() if m.name.endswith("pcaps/combined.csv")), None)
        if combined is None:
            skipped.append((tar_path.name, "no combined.csv"))
            continue
        df = pd.read_csv(io.BytesIO(tf.extractfile(combined).read()))

    df["Flow ID"] = (df["src_ip"].astype(str) + " " + df["dst_ip"].astype(str) + " "
                     + df["src_port"].astype(str) + " " + df["dst_port"].astype(str) + " "
                     + df["transport_proto"].astype(str))
    df["class"] = df["class"].astype(int)
    m = df.merge(gt, on="Flow ID")
    m = m[m["type"].isin(TYPES)].copy()
    m["w"] = 1 / m["packet_counts"]

    ct = m.pivot_table(index="type", columns="class", values="w", aggfunc="sum").fillna(0)
    ids = [c for c in ct.columns if c != 0]
    mapping = {t: max(ids, key=lambda i: ct.loc[t, i] if i in ct.columns else 0) for t in TYPES}
    if len(set(mapping.values())) != 7:
        skipped.append((tar_path.name, f"non-bijective id map: {mapping}"))
        continue

    cols = [mapping[t] for t in TYPES] + ([0] if 0 in ct.columns else [])
    ctn = ct.reindex(index=TYPES, columns=cols).fillna(0)
    ctn.columns = TYPES + (["nenhuma"] if 0 in ct.columns else [])
    ctn = ctn.div(ctn.sum(axis=1), axis=0)

    ref = per_class[(per_class["seed"] == seed) & (per_class["model"] == model)].set_index("class")["recall"]
    for t in TYPES:
        if t in ref.index and abs(ctn.loc[t, t] - ref[t]) > 0.005:
            skipped.append((tar_path.name, f"validation {t}: diag={ctn.loc[t, t]:.3f} ref={ref[t]:.3f}"))
    for t in TYPES:
        for cj in ctn.columns:
            rows.append({"model": model, "seed": seed, "true": t, "pred": cj, "frac": ctn.loc[t, cj]})

out = paths.OUTPUT / "confusion_per_seed.csv"
pd.DataFrame(rows).to_csv(out, index=False)
runs = pd.DataFrame(rows).groupby(["model", "seed"]).ngroups if rows else 0
print(f"wrote {out}: {runs} runs")
for name, why in skipped:
    print(f"  skipped/flagged {name}: {why}")
