import sys
import paths
sys.path.insert(0, str(paths.SPP_SOLVER))
import pandas as pd
from pathlib import Path
from SPP.spp import SPP
import logging; logging.getLogger("SPP").setLevel(logging.ERROR)

MODELS_DIR = paths.MODELS
N_CLASSES = 7; N_FEATURES = 32
pd.set_option("display.max_colwidth", None); pd.set_option("display.width", 200)

results = {}
for name in ["rf","xgboost","lightgbm","catboost"]:
    d = MODELS_DIR/name
    w = pd.read_csv(d/"importance_weights.csv"); f1 = pd.read_csv(d/"f1_scores.csv")
    spp = SPP(n_classes=N_CLASSES, n_features=N_FEATURES, unwanted_classes=[],
              use_case="TON-IOT", weights_df=w, f1_df=f1, fix_level=5)  # -> 4 clusters
    sol = spp.solve_spp_greedy(save=False, show_plot_gain=False, print_console=False)
    sol.to_csv(d/"spp_4cluster.csv", index=False)
    results[name] = sol
    print(f"\n===== {name.upper()} — 4-cluster partition =====")
    for _, row in sol.iterrows():
        print(f"  C{row['Cluster']}: {row['Class List']}")
        print(f"       feats({len(row['Feature List'])}): {row['Feature List']}")

# DoS co-location check: which cluster holds ddos & dos
print("\n===== DoS grouping (ddos, dos) per model =====")
for name, sol in results.items():
    loc = {}
    for _, row in sol.iterrows():
        for c in ("ddos","dos"):
            if c in row["Class List"]: loc[c] = row["Cluster"]
    same = loc.get("ddos")==loc.get("dos")
    print(f"  {name:9s}: ddos->C{loc.get('ddos')}, dos->C{loc.get('dos')}  {'(together)' if same else '(split)'}")
print("\nDONE")
