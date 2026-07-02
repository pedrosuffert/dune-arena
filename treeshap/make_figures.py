"""Thesis figures from the multi-seed campaign CSVs (Chapter 6 package).

Inputs (data/output/): multiseed_offline.csv, multiseed_innetwork.csv,
stage1_multiseed.csv, per_class_innetwork.csv, importance_snapshots/.
Outputs: data/output/figs/*.pdf (vector, PT-BR labels).
"""
import ast
from itertools import combinations
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import paths

MODELS = ["rf", "xgboost", "lightgbm", "catboost"]
NICE = {"rf": "RF", "xgboost": "XGBoost", "lightgbm": "LightGBM", "catboost": "CatBoost"}
CLASSES = ["ddos", "dos", "normal", "scanning", "injection", "password", "xss"]
FIGS = paths.OUTPUT / "figs"
FIGS.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.size": 9, "figure.dpi": 150})

off = pd.read_csv(paths.OUTPUT / "multiseed_offline.csv")
inn = pd.read_csv(paths.OUTPUT / "multiseed_innetwork.csv")
s1 = pd.read_csv(paths.OUTPUT / "stage1_multiseed.csv")
pc = pd.read_csv(paths.OUTPUT / "per_class_innetwork.csv")
fair = off[off.regime == "fair"]


def save(fig, name):
    fig.tight_layout()
    fig.savefig(FIGS / name)
    plt.close(fig)
    print(f"wrote figs/{name}")


# ── Fig: Stage-1 comparison (macro + DoS-F1, mean±std over seeds) ────────────
fig, ax = plt.subplots(figsize=(4.8, 2.8))
x = np.arange(len(MODELS))
for i, (col, label, off_x) in enumerate([("macro", "Macro-F1", -0.18), ("dos_f1", "F1 DoS (ddos+dos)", 0.18)]):
    mu = [100 * s1[s1.model == m][col].mean() for m in MODELS]
    sd = [100 * s1[s1.model == m][col].std() for m in MODELS]
    ax.bar(x + off_x, mu, 0.34, yerr=sd, capsize=3, label=label)
ax.set_xticks(x, [NICE[m] for m in MODELS])
ax.set_ylabel("F1 (%)")
ax.set_ylim(90, 100)
ax.legend(frameon=False, loc="upper left", ncols=2, fontsize=8)
ax.set_title("Estágio 1: validação interna, 10 sementes", fontsize=9)
save(fig, "fig_stage1_comparacao.pdf")

# ── Fig: co-partition matrix (fair regime, 40 model-seed cases) ──────────────
co = pd.DataFrame(0, index=CLASSES, columns=CLASSES, dtype=float)
n_cases = 0
for p in fair["partition"]:
    n_cases += 1
    for blk in p.split(" "):
        cs = blk.strip("{}").split(",")
        for a in cs:
            for b in cs:
                co.loc[a, b] += 1
co /= n_cases
fig, ax = plt.subplots(figsize=(4.6, 3.9))
im = ax.imshow(co.values, cmap="Blues", vmin=0, vmax=1)
ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=45, ha="right")
ax.set_yticks(range(len(CLASSES)), CLASSES)
for i in range(len(CLASSES)):
    for j in range(len(CLASSES)):
        v = co.values[i, j]
        ax.text(j, i, f"{v:.2f}", ha="center", va="center",
                color="white" if v > 0.6 else "black", fontsize=7)
fig.colorbar(im, label="freq. no mesmo cluster")
ax.set_title("")
save(fig, "fig_coparticionamento.pdf")

# ── Fig: offline vs in-network paired per seed ───────────────────────────────
fig, axes = plt.subplots(1, 4, figsize=(9.6, 2.7), sharey=True)
for ax, m in zip(axes, MODELS):
    o = fair[fair.model == m].set_index("seed")["macro"]
    i = inn[inn.model == m].set_index("seed")["macro"] * 100
    seeds = sorted(set(o.index) & set(i.index))
    for s_ in seeds:
        ax.plot([0, 1], [o[s_], i[s_]], color="gray", lw=0.6, alpha=0.6)
        ax.scatter([0, 1], [o[s_], i[s_]], s=8, color="tab:blue")
    ax.plot([0, 1], [o.mean(), i.mean()], color="tab:red", lw=2, label="média")
    ax.set_xticks([0, 1], ["offline", "in-network"])
    ax.set_xlim(-0.3, 1.3)
    ax.set_title(NICE[m])
axes[0].set_ylabel("Macro-F1 (%)")
axes[0].legend(frameon=False, fontsize=7)
pass
save(fig, "fig_offline_vs_innetwork.pdf")

# ── Fig: per-class in-network F1 heatmap (mean over seeds) ───────────────────
pcc = pc[pc["class"].isin(CLASSES)]
mat = pcc.pivot_table(index="model", columns="class", values="f1", aggfunc="mean")
mat = mat.loc[MODELS, CLASSES] * 100
fig, ax = plt.subplots(figsize=(5.6, 2.4))
im = ax.imshow(mat.values, cmap="RdYlGn", vmin=85, vmax=100)
ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=45, ha="right")
ax.set_yticks(range(len(MODELS)), [NICE[m] for m in MODELS])
for i in range(len(MODELS)):
    for j in range(len(CLASSES)):
        ax.text(j, i, f"{mat.values[i, j]:.1f}", ha="center", va="center", fontsize=7)
fig.colorbar(im, label="F1 (%)")
ax.set_title("")
save(fig, "fig_f1_por_classe_innetwork.pdf")

# ── Fig: TreeSHAP heatmap per model (mean importance over seeds) ─────────────
snap = paths.OUTPUT / "importance_snapshots"
frames = []
for f in snap.glob("seed*_*.csv"):
    seed, model = f.stem.replace("seed", "").split("_", 1)
    d = pd.read_csv(f)
    d["seed"], d["model"] = int(seed), model
    frames.append(d)
imp = pd.concat(frames, ignore_index=True)
feat_cols = [c for c in imp.columns if c not in ("classes", "seed", "model")]
mean_imp = imp.groupby(["model", "classes"])[feat_cols].mean()
top = mean_imp.groupby(level="model").mean().mean(0).sort_values(ascending=False)
TOPK = list(top.index[:12])
fig, axes = plt.subplots(2, 2, figsize=(9.5, 6.2), sharex=True, sharey=True)
for ax, m in zip(axes.flat, MODELS):
    M = mean_imp.loc[m].loc[CLASSES, TOPK]
    im = ax.imshow(M.values, cmap="viridis", vmin=0, vmax=float(mean_imp[TOPK].max().max()))
    ax.set_title(NICE[m], fontsize=9)
    ax.set_yticks(range(len(CLASSES)), CLASSES, fontsize=7)
    ax.set_xticks(range(len(TOPK)), TOPK, rotation=60, ha="right", fontsize=6.5)
fig.colorbar(im, ax=axes, label="importância TreeSHAP (normalizada por classe)", shrink=0.8)
pass
fig.savefig(FIGS / "fig_treeshap_heatmap.pdf", bbox_inches="tight")
plt.close(fig)
print("wrote figs/fig_treeshap_heatmap.pdf")

# ── Stat: top-5 TreeSHAP rank overlap between models (per class, mean/seeds) ─
print("\nTop-5 TreeSHAP overlap entre modelos (média sobre classes e sementes):")
rows = []
for (s_, c), grp in imp.groupby(["seed", "classes"]):
    g = grp.set_index("model")[feat_cols]
    for a, b in combinations(MODELS, 2):
        ta = set(g.loc[a].nlargest(5).index)
        tb = set(g.loc[b].nlargest(5).index)
        rows.append({"pair": f"{NICE[a]}–{NICE[b]}", "overlap": len(ta & tb) / 5})
ov = pd.DataFrame(rows).groupby("pair")["overlap"].mean().sort_values(ascending=False)
print(ov.to_string())
ov.to_csv(paths.OUTPUT / "treeshap_top5_overlap.csv")
print("\nDONE")
