"""Fig: matrizes de confusao in-network (media de 10 seeds), 2x2 por familia.

Input: data/output/confusion_per_seed.csv (gerado por extract_confusion.py).
Estilo alinhado ao make_figures.py (viridis, paineis 2x2, colorbar
compartilhada, PDF vetorial, rotulos pt-BR).

Output: data/output/figs/fig_confusao_innetwork.pdf
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import paths

FIGS = paths.OUTPUT / "figs"
FIGS.mkdir(parents=True, exist_ok=True)
OUT = FIGS / "fig_confusao_innetwork.pdf"

MODELS = ["rf", "xgboost", "lightgbm", "catboost"]
NICE = {"rf": "RF", "xgboost": "XGBoost", "lightgbm": "LightGBM", "catboost": "CatBoost"}
CLASSES = ["ddos", "dos", "normal", "scanning", "injection", "password", "xss"]
PRED = CLASSES + ["nenhuma"]
PRED_LABELS = CLASSES + ["sem classe"]

plt.rcParams.update({"font.size": 9, "figure.dpi": 150})

conf = pd.read_csv(paths.OUTPUT / "confusion_per_seed.csv")
mean = conf.groupby(["model", "true", "pred"])["frac"].mean().mul(100)

fig, axes = plt.subplots(2, 2, figsize=(8.8, 6.8), sharex=True, sharey=True)
for ax, m in zip(axes.flat, MODELS):
    M = np.zeros((len(CLASSES), len(PRED)))
    for i, t in enumerate(CLASSES):
        row = mean.loc[m, t]
        for j, p in enumerate(PRED):
            M[i, j] = row.get(p, 0.0)
    im = ax.imshow(M, cmap="viridis", vmin=0, vmax=100)
    ax.set_title(NICE[m], fontsize=9)
    ax.set_xticks(range(len(PRED)), PRED_LABELS, rotation=45, ha="right", fontsize=7.5)
    ax.set_yticks(range(len(CLASSES)), CLASSES, fontsize=7.5)
    for i in range(len(CLASSES)):
        for j in range(len(PRED)):
            v = M[i, j]
            ax.text(j, i, f"{v:.1f}".replace(".", ","), ha="center", va="center",
                    color="black" if v > 60 else "white", fontsize=6.2)
fig.supylabel("classe verdadeira", fontsize=9)
fig.supxlabel("classe predita", fontsize=9, y=0.015)
fig.colorbar(im, ax=axes, label="% da classe verdadeira", shrink=0.75)
fig.savefig(OUT, bbox_inches="tight")
print("wrote", OUT)
