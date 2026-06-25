"""
Build per-class TreeSHAP importance matrices + per-class F1 for all 4 models,
in DUNE SPP format:
  importance_weights.csv : col 'classes' + one col per feature
  f1_scores.csv          : col 'class','f1_score'
"""
import pandas as pd, numpy as np, joblib
from pathlib import Path
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import f1_score
import shap
import paths
import os as _os; SEED = int(_os.environ.get("DUNE_SEED", "42"))

TRAIN_CSV  = paths.TRAIN_CSV
MODELS_DIR = paths.MODELS
FEATS = ["ip.len","ip.ttl","tcp.flags.syn","tcp.flags.ack","tcp.flags.push",
    "tcp.flags.fin","tcp.flags.reset","tcp.flags.ecn","ip.proto","srcport",
    "dstport","ip.hdr_len","ip.tos","tcp.window_size_value","tcp.hdr_len",
    "udp.length","Min Packet Length","Max Packet Length","Packet Length Mean",
    "Packet Length Total","UDP Len Min","UDP Len Max","Flow IAT Min",
    "Flow IAT Max","Flow IAT Mean","Time to Inference","SYN Flag Count",
    "ACK Flag Count","PSH Flag Count","FIN Flag Count","RST Flag Count","ECE Flag Count"]

df = pd.read_csv(TRAIN_CSV)
X = df[FEATS].fillna(0).values
le0 = joblib.load(MODELS_DIR/"rf"/"unconstrained_model.sav")["label_encoder"]
y = le0.transform(df["Label"].values)
classes = list(le0.classes_)
# F4: split by Flow ID (no within-flow leakage); same split as train_models.py
tr_i, va_i = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, df["Flow ID"].values))
X_tr, X_val, y_tr, y_val = X[tr_i], X[va_i], y[tr_i], y[va_i]

def per_class_shap(clf, Xbg):
    expl = shap.TreeExplainer(clf)
    bg = shap.sample(Xbg, min(500, len(Xbg)), random_state=SEED)
    sv = expl.shap_values(bg)
    # Normalize to list[ per-class array (samples,features) ]
    if isinstance(sv, list):                       # old API: list over classes
        mats = [np.abs(v).mean(0) for v in sv]
    elif sv.ndim == 3:                             # (samples,features,classes)
        mats = [np.abs(sv[:,:,c]).mean(0) for c in range(sv.shape[2])]
    else:                                          # (samples,features) -> single
        mats = [np.abs(sv).mean(0)] * len(classes)
    return np.array(mats)                          # (n_classes, n_features)

for name in ["rf","xgboost","lightgbm","catboost"]:
    d = MODELS_DIR/name
    blob = joblib.load(d/"unconstrained_model.sav")
    clf = blob["model"]
    print(f"[{name}] SHAP per-class...")
    M = per_class_shap(clf, X_tr)                  # (n_classes,n_features)
    # F3: per-class normalize to sum 1, matching DUNE PCFI contract (pcfi.py:115)
    # so the SPP gain's 1/n_features uniform threshold is meaningful.
    M = M / np.where(M.sum(axis=1, keepdims=True) == 0, 1, M.sum(axis=1, keepdims=True))
    imp_df = pd.DataFrame(M, columns=FEATS)
    imp_df.insert(0, "classes", classes)
    imp_df.to_csv(d/"importance_weights.csv", index=False)
    # per-class F1 on val
    y_pred = clf.predict(X_val)
    f1s = f1_score(y_val, y_pred, average=None, labels=range(len(classes)))
    f1_df = pd.DataFrame({"class": classes, "f1_score": f1s})
    f1_df.to_csv(d/"f1_scores.csv", index=False)
    print(imp_df.round(4).to_string())
    print(f1_df.round(4).to_string())
    print()
print("DONE")
