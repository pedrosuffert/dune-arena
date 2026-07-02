"""Multi-seed campaign: offline Stages 1-5 (both Stage-4 regimes) + in-network
line-topology deploy (fair regime), per seed x model. Fault-tolerant, appends
incrementally, safe to re-run (skips seeds already in both CSVs).

Per seed:
  1. Stages 1-3 once (train_models, build_importance, run_spp) under DUNE_SEED.
  2. stage45 with DUNE_ARENA_FAIR_FEATURES=1 -> offline 'fair' rows (macro, tcam,
     partition, sequence) for the 4 models.
  3. Per model: train_submodels + deploy_stage6 + `make run-linear-test` on the
     BMv2 line topology, score -> in-network row (macro, collisions).
  4. stage45 with DUNE_ARENA_FAIR_FEATURES=0 -> offline 'original' rows (DUNE's
     released Stage 4; overwrites stage4_results, so it runs AFTER the deploys).

Usage: multiseed.py [seed ...]      (default: 1..10)
Env:   MS_MODELS="rf xgboost"       limit models
       MS_PPS=500                   tcpreplay rate for the line run
Outputs: data/output/multiseed_offline.csv   (seed, model, regime, macro, tcam, partition, sequence)
         data/output/multiseed_innetwork.csv (seed, model, macro, weighted, micro, collisions)
"""
import ast
import csv
import os
import re
import subprocess
import sys

import pandas as pd

import paths

MODELS = os.environ.get("MS_MODELS", "rf xgboost lightgbm catboost").split()
SEEDS = [int(x) for x in sys.argv[1:]] or list(range(1, 11))
PPS = int(os.environ.get("MS_PPS", "500"))
TESTBED = paths.ROOT / "testbed"
TS = paths.ROOT / "treeshap"
RESULT = TESTBED / f"results_p1_ss1_s1_l1_h1_{PPS}pps.txt"
OUT_OFF = paths.OUTPUT / "multiseed_offline.csv"
OUT_NET = paths.OUTPUT / "multiseed_innetwork.csv"
PY = sys.executable

MAKE_RUN = (
    "source ~/src/p4setup.bash && cd {tb} && sudo mn -c >/dev/null 2>&1; "
    "make run-linear-test MODELS=configs/models/{m}_ton.json "
    "TEST_PCAP=../data/output/ToN_IoT_test.pcap "
    "GROUND_TRUTH_FILE=../data/output/ToN_IoT_Flow_PktCounts.csv "
    "TEST_PPS={pps} PODS=1 SPINES=1 LEAFS=1 SUPER_SPINES=1 HOSTS_PER_LEAF=1 "
    "SAVE_RESULTS=NO"
)


def run_py(script, seed, fair=None, args=(), timeout=None):
    env = dict(os.environ, DUNE_SEED=str(seed))
    if fair is not None:
        env["DUNE_ARENA_FAIR_FEATURES"] = "1" if fair else "0"
    subprocess.run([PY, str(TS / script), *args], env=env, check=True, timeout=timeout)


def offline_row(m):
    perf = paths.MODELS / m / "stage4_results/perf_results"
    per_class = pd.read_csv(perf / "score_per_cluster_per_class_df.csv")
    macro = per_class["Cluster_F1_Score"].mean()
    ci = pd.read_csv(perf / "cluster_info_df.csv", converters={"Class List": ast.literal_eval})
    tcam = sum(ci["Total_TCAM_Usage"].to_list()[1:])
    part = " ".join("{" + ",".join(sorted(c)) + "}" for c in ci["Class List"])
    seq = (paths.MODELS / m / "stage5_results/sequence.txt").read_text().strip()
    return macro, tcam, part, seq


def writer(path, header):
    new = not path.exists()
    f = open(path, "a", newline="")
    w = csv.writer(f)
    if new:
        w.writerow(header)
        f.flush()
    return f, w


def seeds_done(path, expect):
    """Seeds with the expected number of non-empty result rows."""
    if not path.exists():
        return set()
    df = pd.read_csv(path)
    df = df[df["macro"].notna()]
    counts = df.groupby("seed").size()
    return set(counts[counts >= expect].index)


f_off, w_off = writer(OUT_OFF, ["seed", "model", "regime", "macro", "tcam", "partition", "sequence"])
f_net, w_net = writer(OUT_NET, ["seed", "model", "macro", "weighted", "micro", "collisions"])
done_off = seeds_done(OUT_OFF, len(MODELS) * 2)
done_net = seeds_done(OUT_NET, len(MODELS))

for s in SEEDS:
    if s in done_off and s in done_net:
        print(f"seed {s}: already complete, skipping", flush=True)
        continue
    try:
        print(f"=== seed {s}: Stages 1-3 ===", flush=True)
        for sc in ["train_models.py", "build_importance.py", "run_spp.py"]:
            run_py(sc, s)

        print(f"=== seed {s}: Stage 4+5 (fair) ===", flush=True)
        run_py("stage45.py", s, fair=True)
        fair_rows = {m: offline_row(m) for m in MODELS}
        for m in MODELS:
            w_off.writerow([s, m, "fair", *fair_rows[m]])
        f_off.flush()

        for m in MODELS:
            print(f"=== seed {s} {m}: deploy + line run ===", flush=True)
            run_py("train_submodels.py", s, args=(m,))
            run_py("deploy_stage6.py", s, args=(m,))
            if RESULT.exists():
                RESULT.unlink()
            try:
                subprocess.run(["bash", "-c", MAKE_RUN.format(tb=TESTBED, m=m, pps=PPS)],
                               check=False, timeout=2400,
                               stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            except subprocess.TimeoutExpired:
                print(f"seed {s} {m}: RUN TIMEOUT", flush=True)
            macro = wgt = mic = col = ""
            if RESULT.exists():
                t = RESULT.read_text()
                g = lambda p: (re.search(p, t) or [None, ""])[1]
                macro, wgt, mic = g(r"Macro=([0-9.]+)"), g(r"Weighted=([0-9.]+)"), g(r"Micro=([0-9.]+)")
                col = g(r"Collision count: (\d+)")
            w_net.writerow([s, m, macro, wgt, mic, col])
            f_net.flush()
            print(f"seed {s} {m}: macro={macro} collisions={col}", flush=True)

        print(f"=== seed {s}: Stage 4+5 (original regime, offline only) ===", flush=True)
        run_py("stage45.py", s, fair=False)
        for m in MODELS:
            w_off.writerow([s, m, "original", *offline_row(m)])
        f_off.flush()
    except Exception as ex:
        print(f"seed {s} FAILED: {ex}", flush=True)

f_off.close()
f_net.close()
print("MULTISEED_DONE", flush=True)
