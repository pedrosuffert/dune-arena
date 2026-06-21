"""Single results view: gather per-model Stage 4/5 outputs into one comparison table.

Real macro-F1 (mean over the 7 classes), DUNE TCAM, class partition, Stage-5 sequence.
Reads only persisted artifacts (no /tmp, no stdout scraping).
"""
import ast
import pandas as pd
import paths

MODELS = ["rf", "xgboost", "lightgbm", "catboost"]


def model_row(m):
    perf = paths.MODELS / m / "stage4_results" / "perf_results"
    per_class = pd.read_csv(perf / "score_per_cluster_per_class_df.csv")
    macro = per_class["Cluster_F1_Score"].mean()                 # real 7-class macro
    ci = pd.read_csv(perf / "cluster_info_df.csv", converters={"Class List": ast.literal_eval})
    tcam = sum(ci["Total_TCAM_Usage"].to_list()[1:])             # DUNE metric: skips entry cluster 0
    partition = " ".join("{" + ",".join(sorted(c)) + "}" for c in ci["Class List"])
    seq_f = paths.MODELS / m / "stage5_results" / "sequence.txt"
    seq = seq_f.read_text().strip() if seq_f.exists() else "n/a"
    return {"model": m, "macro_f1": round(macro, 2), "tcam": round(tcam, 2),
            "sequence": seq, "partition": partition}


rows = [model_row(m) for m in MODELS]
df = pd.DataFrame(rows)
print(df[["model", "macro_f1", "tcam", "sequence"]].to_string(index=False))
print()
for r in rows:
    print(f"  {r['model']:9} {r['partition']}")

out = paths.OUTPUT / "results_comparison.csv"
out.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(out, index=False)
print(f"\nwrote {out}")
