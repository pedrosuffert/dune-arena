"""
Stage 6a: train + save per-cluster RF sub-models from Stage-4 selected hyperparams.
Replicates DUNE modelAnalyzer training (Other-relabel, flow-weighted samples).
Saves plain sklearn RandomForestClassifier .sav (feature_names_in_ = selected feats)
so DUNE's convert_RF_and_populate_tables.py can read it.
Usage: python3 train_submodels.py <model_name>   e.g. rf
"""
import sys, ast, pickle
import numpy as np, pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
import paths
import os as _os; SEED = int(_os.environ.get("DUNE_SEED", "42"))

MODEL = sys.argv[1] if len(sys.argv) > 1 else "rf"
N = 4
RB = paths.DATA
CI = RB/"models"/MODEL/"stage4_results"/"perf_results"/"cluster_info_df.csv"
OUT = RB/"models"/MODEL/"submodels"; OUT.mkdir(exist_ok=True)

# ---- load cluster best-model info ----
ci = pd.read_csv(CI, converters={"Class List": ast.literal_eval, "Feature List": ast.literal_eval})

# ---- load + prep train data (same as DUNE modelAnalyzer._prepare_data) ----
train = pd.read_csv(RB/"stage4"/"train_4_pkts.csv")
flc = pd.read_csv(RB/"stage4"/"flow_counts_all.csv")
cnt = flc.set_index("Flow ID")["packet_counts"].to_dict()
train["pkt_count"] = train["Flow ID"].map(cnt)
train = train.sample(frac=1, random_state=SEED).dropna(subset=["srcport","dstport","pkt_count"])

def sample_nature(r):
    return "pkt" if (r["Min Packet Length"]==-1 and r["Max Packet Length"]==-1
                     and r["Flow IAT Min"]==-1 and r["Flow IAT Max"]==-1) else "flw"
train["sample_nature"] = train.apply(sample_nature, axis=1)
train["weight"] = np.where(train["sample_nature"]=="flw",
                            (train["pkt_count"]-N+1)/train["pkt_count"], 1/train["pkt_count"])

print(f"=== {MODEL}: training {len(ci)} cluster sub-models ===")
summary = []
for _, row in ci.iterrows():
    cid   = int(row["Cluster"])
    feats = list(row["Feature List"])
    klass = list(row["Class List"])
    ntree = int(row["Tree"]); nleaf = int(row["N_Leaves"])
    classes = klass + ["Other"]                 # real... + Other  (label order)

    df = train.copy()
    df["Label_NEW"] = np.where(df["Label"].isin(klass), df["Label"], "Other")
    y = df["Label_NEW"].map({c:i for i,c in enumerate(classes)}).astype(int)
    X = df[feats]                                # DataFrame -> feature_names_in_
    w = df["weight"].to_list()

    clf = RandomForestClassifier(n_estimators=ntree, max_leaf_nodes=nleaf, max_depth=None,
                                 bootstrap=False, random_state=SEED, n_jobs=-1)
    clf.fit(X, y, sample_weight=w)

    fn = OUT/f"cluster{cid}_T{ntree}_L{nleaf}_F{len(feats)}_N{N}.sav"
    pickle.dump(clf, open(fn, 'wb'))
    depths = [e.tree_.max_depth for e in clf.estimators_]
    summary.append((cid, klass, ntree, nleaf, len(feats), depths))
    print(f"  C{cid} {klass}: T{ntree} L{nleaf} F{len(feats)} depths={depths} classes_={list(clf.classes_)} -> {fn.name}")

print("\nDONE. classes order per cluster (real...+Other) used for label ids 0..n")
