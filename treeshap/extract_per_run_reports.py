"""Recover per-class in-network F1 from the testbed's per-run archives.

Every `make results` archives {pcaps/, logs/, results_*.txt} into
testbed/experiment_<N>.tar.gz. The results txt embeds the full per-class
classification report (pprint'ed dict). This script matches each archive to its
(seed, model) row in multiseed_innetwork.csv by the exact Macro value and emits
a tidy per-class table. Archives that match nothing (smoke runs) are skipped.

Output: data/output/per_class_innetwork.csv
        (seed, model, class, precision, recall, f1, support)
"""
import ast
import re
import tarfile

import pandas as pd

import paths

TESTBED = paths.ROOT / "testbed"
inn = pd.read_csv(paths.OUTPUT / "multiseed_innetwork.csv")
inn["macro_r"] = inn["macro"].round(9)

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
    dm = re.search(r"\{.*\}", txt, re.DOTALL)
    if not (mm and dm):
        skipped.append((tar_path.name, "unparseable"))
        continue
    hit = inn[inn["macro_r"] == round(float(mm.group(1)), 9)]
    if len(hit) != 1:
        skipped.append((tar_path.name, f"macro match x{len(hit)} (smoke or dup)"))
        continue
    seed, model = int(hit.iloc[0]["seed"]), hit.iloc[0]["model"]
    try:
        rep = ast.literal_eval(dm.group(0))
    except Exception as e:
        skipped.append((tar_path.name, f"report parse: {e}"))
        continue
    for cls, v in rep.items():
        if not isinstance(v, dict) or "f1-score" not in v:
            continue
        rows.append({"seed": seed, "model": model, "class": cls,
                     "precision": v.get("precision"), "recall": v.get("recall"),
                     "f1": v["f1-score"], "support": v.get("support")})

out = paths.OUTPUT / "per_class_innetwork.csv"
pd.DataFrame(rows).to_csv(out, index=False)
print(f"wrote {out}: {len(rows)} rows "
      f"({pd.DataFrame(rows)['seed'].nunique() if rows else 0} seeds)")
for name, why in skipped:
    print(f"  skipped {name}: {why}")
