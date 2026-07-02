"""Stage-1 multi-seed extraction + per-seed TreeSHAP snapshots (post-campaign).

Re-runs train_models.py + build_importance.py per seed (both deterministic under
DUNE_SEED), parses each model's internal-validation metrics, and stashes the
per-class importance matrix per (seed, model) for rank-stability analysis.

Run AFTER multiseed.py (shares data/models/ working dirs).

Outputs:
  data/output/stage1_multiseed.csv                   (seed, model, macro, dos_f1)
  data/output/importance_snapshots/seed<s>_<m>.csv   (copy of importance_weights.csv)
"""
import csv
import os
import re
import shutil
import subprocess
import sys

import paths

MODELS = ["rf", "xgboost", "lightgbm", "catboost"]
SEEDS = [int(x) for x in sys.argv[1:]] or list(range(1, 11))
TS = paths.ROOT / "treeshap"
SNAP = paths.OUTPUT / "importance_snapshots"
SNAP.mkdir(parents=True, exist_ok=True)
OUT = paths.OUTPUT / "stage1_multiseed.csv"

new = not OUT.exists()
f = open(OUT, "a", newline="")
w = csv.writer(f)
if new:
    w.writerow(["seed", "model", "macro", "dos_f1"])

for s in SEEDS:
    env = dict(os.environ, DUNE_SEED=str(s))
    print(f"=== seed {s} ===", flush=True)
    subprocess.run([sys.executable, str(TS / "train_models.py")], env=env, check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, str(TS / "build_importance.py")], env=env, check=True,
                   stdout=subprocess.DEVNULL)
    for m in MODELS:
        t = (paths.MODELS / m / "metrics.txt").read_text()
        macro = re.search(r"Macro-F1: ([0-9.]+)", t).group(1)
        dos = re.search(r"DoS-F1 \(ddos\+dos\): ([0-9.]+)", t).group(1)
        w.writerow([s, m, macro, dos])
        shutil.copy(paths.MODELS / m / "importance_weights.csv", SNAP / f"seed{s}_{m}.csv")
        print(f"  {m}: macro={macro} dos={dos}", flush=True)
    f.flush()
f.close()
print("STAGE1_EXTRACT_DONE", flush=True)
