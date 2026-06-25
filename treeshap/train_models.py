"""
Train RF, XGBoost, LightGBM, CatBoost on DUNE 34-feature data (7 classes).
Outputs for each model:
  ~/realbuild/models/<model>/unconstrained_model.sav    (joblib)
  ~/realbuild/models/<model>/feature_importance.csv     (TreeSHAP)
  ~/realbuild/models/<model>/metrics.txt
"""
import pandas as pd
import numpy as np
import joblib, json, os
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report, f1_score
import xgboost as xgb
import lightgbm as lgb
import catboost as cb
import shap

import paths
import os as _os; SEED = int(_os.environ.get("DUNE_SEED", "42"))
TRAIN_CSV = paths.TRAIN_CSV
MODELS_DIR = paths.MODELS
MODELS_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_COLS = [
    "ip.len","ip.ttl","tcp.flags.syn","tcp.flags.ack","tcp.flags.push",
    "tcp.flags.fin","tcp.flags.reset","tcp.flags.ecn","ip.proto","srcport",
    "dstport","ip.hdr_len","ip.tos","tcp.window_size_value","tcp.hdr_len",
    "udp.length","Min Packet Length","Max Packet Length","Packet Length Mean",
    "Packet Length Total","UDP Len Min","UDP Len Max","Flow IAT Min",
    "Flow IAT Max","Flow IAT Mean","Time to Inference","SYN Flag Count",
    "ACK Flag Count","PSH Flag Count","FIN Flag Count","RST Flag Count",
    "ECE Flag Count"
]

print("Loading train data...")
df = pd.read_csv(TRAIN_CSV)
X = df[FEATURE_COLS].fillna(0).values
y_raw = df["Label"].values
le = LabelEncoder()
y = le.fit_transform(y_raw)
classes = le.classes_.tolist()
print(f"Classes: {classes}")
print(f"Shape: {X.shape}")
print(pd.Series(y_raw).value_counts())

# F4: split by Flow ID so packets of one flow never span train/val (no leakage)
tr_i, va_i = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, df["Flow ID"].values))
X_tr, X_val, y_tr, y_val = X[tr_i], X[va_i], y[tr_i], y[va_i]

def save_model(name, clf, X_bg):
    d = MODELS_DIR / name
    d.mkdir(exist_ok=True)
    joblib.dump({"model": clf, "label_encoder": le, "feature_cols": FEATURE_COLS}, d/"unconstrained_model.sav")
    # TreeSHAP
    print(f"  [{name}] computing SHAP...")
    explainer = shap.TreeExplainer(clf)
    bg = shap.sample(X_bg, min(500, len(X_bg)), random_state=SEED)
    sv = explainer.shap_values(bg)
    # sv shape: (samples, features) for binary, (samples, features, classes) for multi
    if isinstance(sv, list):
        imp = np.mean([np.abs(v).mean(0) for v in sv], axis=0)
    else:
        imp = np.abs(sv).mean(axis=(0, -1)) if sv.ndim == 3 else np.abs(sv).mean(0)
    fi_df = pd.DataFrame({"feature": FEATURE_COLS, "importance": imp}).sort_values("importance", ascending=False)
    fi_df.to_csv(d/"feature_importance.csv", index=False)
    print(fi_df.head(10).to_string())
    # Val metrics
    y_pred = clf.predict(X_val)
    report = classification_report(y_val, y_pred, target_names=classes)
    macro_f1 = f1_score(y_val, y_pred, average="macro")
    dos_idx = [i for i,c in enumerate(classes) if c in {"ddos","dos"}]
    dos_f1 = f1_score(y_val, y_pred, labels=dos_idx, average="macro")
    with open(d/"metrics.txt","w") as f:
        f.write(f"Macro-F1: {macro_f1:.4f}\nDoS-F1 (ddos+dos): {dos_f1:.4f}\n\n{report}")
    print(f"  [{name}] Macro-F1={macro_f1:.4f}  DoS-F1={dos_f1:.4f}")

# --- RF ---
print("\n=== RandomForest ===")
rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=SEED)
rf.fit(X_tr, y_tr)
save_model("rf", rf, X_tr)

# --- XGBoost ---
print("\n=== XGBoost ===")
xgb_clf = xgb.XGBClassifier(n_estimators=100, n_jobs=-1, random_state=SEED,
                              use_label_encoder=False, eval_metric="mlogloss",
                              tree_method="hist")
xgb_clf.fit(X_tr, y_tr)
save_model("xgboost", xgb_clf, X_tr)

# --- LightGBM ---
print("\n=== LightGBM ===")
lgb_clf = lgb.LGBMClassifier(n_estimators=100, n_jobs=-1, random_state=SEED, verbose=-1)
lgb_clf.fit(X_tr, y_tr)
save_model("lightgbm", lgb_clf, X_tr)

# --- CatBoost ---
print("\n=== CatBoost ===")
cb_clf = cb.CatBoostClassifier(iterations=100, random_seed=SEED, verbose=0, thread_count=-1)
cb_clf.fit(X_tr, y_tr)
save_model("catboost", cb_clf, X_tr)

print("\n=== ALL DONE ===")
for name in ["rf","xgboost","lightgbm","catboost"]:
    mf = MODELS_DIR/name/"metrics.txt"
    if mf.exists():
        print(f"\n--- {name} ---")
        print(open(mf).read()[:300])
