"""Drive DUNE Stage 4 (grid) + Stage 5 (TSP sequencing) for all 4 models.

Replaces the manual params.ini editing: paths.py stamps each model's paths,
then we invoke DUNE's own scripts. Run from anywhere: `uv run python treeshap/stage45.py`.
"""
import re
import shutil
import subprocess
import sys

import paths

MODELS = ["rf", "xgboost", "lightgbm", "catboost"]


def _run(cwd, script):
    subprocess.run([sys.executable, script], cwd=str(cwd), check=True)


for m in MODELS:
    paths.stamp_stage4(m)
    res = paths.MODELS / m / "stage4_results"
    if res.exists():
        shutil.rmtree(res)            # clear stale per-cluster CSVs from a prior partition
    (res / "perf_results").mkdir(parents=True, exist_ok=True)
    print(f"=== Stage 4: {m} ===")
    _run(paths.ROOT / "cluster_analysis" / "src", "run_cluster_analysis.py")

for m in MODELS:
    paths.stamp_stage5(m)
    out = paths.MODELS / m / "stage5_results"
    out.mkdir(parents=True, exist_ok=True)
    print(f"=== Stage 5: {m} ===")
    p = subprocess.run([sys.executable, "model_sequencing.py"],
                       cwd=str(paths.ROOT / "model_sequencing" / "src"),
                       check=True, capture_output=True, text=True)
    mseq = re.search(r"sequence of the blocks is: (\[[^\]]*\])", p.stdout + p.stderr)
    seq = mseq.group(1) if mseq else "n/a"
    (out / "sequence.txt").write_text(seq)        # persist: collate reads this, not stdout
    print(f"  sequence: {seq}")

print("Stage 4+5 done for all models.")
