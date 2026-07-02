"""Regenerate Stage-6 deploy artifacts for one model into testbed/.

Per cluster (in Stage-5 sequence order): generate the P4, copy the sub-model,
build the config chain, and set the global class-id order in the scorer.
Everything is repo-relative (paths.py); no external checkout needed.

Usage: deploy_stage6.py <rf|xgboost|lightgbm|catboost>
"""
import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd

import paths

m = sys.argv[1]
TESTBED = paths.ROOT / "testbed"
GEN = paths.ROOT / "treeshap" / "generate_p4.py"

ci = pd.read_csv(paths.MODELS / m / "stage4_results/perf_results/cluster_info_df.csv",
                 converters={"Class List": ast.literal_eval}).set_index("Cluster")
seq = ast.literal_eval((paths.MODELS / m / "stage5_results/sequence.txt").read_text().strip())


def submodel(cid):
    r = ci.loc[cid]
    name = f"cluster{cid}_T{int(r['Tree'])}_L{int(r['N_Leaves'])}_F{int(r['Feats'])}_N4.sav"
    p = paths.MODELS / m / "submodels" / name
    assert p.exists(), f"missing {p}"
    return p


# clean stale deploy artifacts from a prior partition
dst = TESTBED / "models" / f"{m}_ton"
if dst.exists():
    shutil.rmtree(dst)
dst.mkdir(parents=True, exist_ok=True)
for old in TESTBED.glob(f"p4sources/{m}_iot_m*.p4"):
    old.unlink()

cfg, offset, global_order = {}, 0, []
for pos, cid in enumerate(seq):
    klass = list(ci.loc[cid, "Class List"])
    sav = submodel(cid)
    mid = pos + 1
    out = TESTBED / "p4sources" / f"{m}_iot_m{mid}.p4"
    subprocess.run([sys.executable, str(GEN), "--sav", str(sav), "--out", str(out),
                    "--model-id", str(mid), "--offset", str(offset),
                    "--classlist", ",".join(klass)], check=True, stdout=subprocess.DEVNULL)
    shutil.copy(sav, dst / sav.name)
    cfg[f"m{mid}"] = {"p4": f"{m}_iot_m{mid}", "files": [f"{m}_ton/{sav.name}"],
                      "previous": (f"m{mid-1}" if pos else None)}
    global_order += klass
    offset += len(klass)

json.dump(cfg, open(TESTBED / "configs/models" / f"{m}_ton.json", "w"), indent=4)

# global class-id order for scoring: id of klass[i] = offset+i+1 along the sequence
cs = TESTBED / "utils/calculate_score.py"
cs.write_text(re.sub(r"classes = \[[^\]]*\]", "classes = " + repr(global_order),
                     cs.read_text(), count=1))

print(f"{m}: seq={seq}  global_order(ids 1..{len(global_order)})={global_order}")
for k, v in cfg.items():
    print(f"  {k}={v['p4']}  {v['files'][0]}")
