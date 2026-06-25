# dune-arena

A fork of [DUNE](https://github.com/nds-group/DUNE) (IEEE INFOCOM 2025) that makes the
choice of Stage-1 tree ensemble *propagate to the deployed P4 sub-models*, and uses that
to fairly compare four ensembles for volumetric DoS detection on TON-IoT.

DUNE splits one tree classifier into hardware-compliant sub-models distributed across
programmable P4 switches. Its pipeline runs six stages: (1) train an unconstrained model,
(2) score per-class feature importance, (3) partition classes with a Set-Partitioning
(SPP) solver, (4) train hardware-compliant Random-Forest sub-models per cluster,
(5) sequence the clusters (TSP), (6) compile and deploy to P4/BMv2.

## What this fork changes

**Model-agnostic importance.** Released DUNE scores importance with PCFI, which is tied to
one model. This fork swaps in **TreeSHAP** so four ensembles compete on equal footing as the
Stage-1 model: **Random Forest, XGBoost, LightGBM, CatBoost**.

**The propagation fix (the core contribution).** In released DUNE, Stage 4 re-derives each
cluster's features from a *fresh* Random Forest's Gini importance over all features, throwing
away the Stage-2 importance. The Stage-1 model therefore reaches hardware only through the
class partition; its feature preferences barely propagate. This fork makes Stage 4 rank each
cluster's features by that cluster's **TreeSHAP importance**, restricted to the BMv2-deployable
features. The Stage-1 choice now flows all the way to the deployed sub-models: their features,
tree configurations, and sequence. The fix lives in
`cluster_analysis/src/model_analysis/modelAnalyzer.py` (`treeshap_feature_sets`, `DEPLOYABLE`).

**Supporting fixes.**
- Per-class normalization of the TreeSHAP matrix, matching the contract PCFI's SPP gain assumes.
- Flow-grouped Stage-1 train/validation split, so no flow leaks across the split.
- Brute-force TSP for Stage 5, dropping the Gurobi dependency.
- A BMv2 P4 source generator with generalized n-class majority voting.

## Results (10 seeds)

Flow-weighted macro-F1 over the seven classes, as mean ± standard deviation across ten
random seeds (real BMv2 fattree in-network, 7 classes, 3258 test flows). Higher is better.

| Stage-1 model | offline macro-F1 | in-network macro-F1 |
|---------------|-----------------:|--------------------:|
| Random Forest | 89.67 ± 0.50 | 89.30 ± 0.93 |
| XGBoost       | 90.27 ± 0.92 | 89.74 ± 0.81 |
| LightGBM      | 90.22 ± 0.50 | 89.82 ± 0.67 |
| CatBoost      | 89.85 ± 0.85 | 89.54 ± 0.71 |

**The four ensembles are statistically tied** — every pairwise comparison is
non-significant (Wilcoxon signed-rank, p = 0.23–1.0), offline and in-network. The
single-seed rankings we first saw were noise.

**The propagation fix still matters, structurally.** With it, the four deploy *distinctly*:
each ranks features by its own TreeSHAP and lands on different sub-model features, tree
configurations, and cluster sequence. What the fix buys is that the Stage-1 choice reaches
hardware at all, something the released pipeline could not express; what it does *not* buy is
a reliably more accurate model.

**Partitions are seed-sensitive.** The RF = LightGBM = CatBoost three-way agreement appears
in only 3 of 10 seeds, and no pair of models shares a partition reliably. The one invariant:
`ddos` and `dos` never land in the same cluster (0 of 40 model-seed cases). For volumetric
DoS, the partition matters more than the algorithm.

**In-network tracks offline** within +0.3 to +0.5 p.p. for every model, so the generated P4 is
faithful to the trained sub-models. Random Forest keeps the least per-flow state (≈328 register
collisions vs ≈900–1000 for the boosting models).

## Repository layout

```
dune-arena/
├── treeshap/                 # contribution layer: the pipeline glue
│   ├── paths.py              #   single path source; env DUNE_FAIR_DATA / DUNE_FAIR_GT override
│   ├── build_label_map.py    #   Flow ID -> Label map from TON-IoT GroundTruth CSVs
│   ├── prepare_dataset.py    #   one-time: merge raw TON-IoT -> train_7class.csv, test pcap, Stage-4 inputs
│   ├── train_models.py       #   Stage 1: train the 4 ensembles + TreeSHAP importance
│   ├── build_importance.py   #   Stage 2: normalized per-class TreeSHAP matrices
│   ├── run_spp.py            #   Stage 3: SPP class partition (4 clusters)
│   ├── stage45.py            #   drives Stage 4 (grid) + Stage 5 (TSP) for all models
│   ├── train_submodels.py    #   Stage 6a: train + save per-cluster RF sub-models
│   ├── generate_p4.py        #   Stage 6b: BMv2 P4 generator (n-class majority voting)
│   └── collate.py            #   one results view -> output/results_comparison.csv
├── cluster_analysis/         # DUNE Stage 4 (modelAnalyzer.py holds the propagation fix)
├── data_generation/          # DUNE Stage 0: pcap -> flow features (tshark)
├── model_partitioning/SPP/   # DUNE Stage 3: SPP solver
├── model_sequencing/         # DUNE Stage 5: TSP sequencing
├── unconstrained_model_analysis/pcfi/   # DUNE's original PCFI, kept for reference
├── testbed/                  # vendored BMv2/Mininet testbed, lab-only (see testbed/PROVENANCE.md)
├── pyproject.toml            # uv project: offline deps
└── uv.lock
```

The DUNE stage directories are kept intact; only `modelAnalyzer.py` carries the fix. PCFI
stays under `unconstrained_model_analysis/` to document what TreeSHAP replaced. The testbed in
`testbed/` is vendored from `nds-group/DUNE-bmv2` with our fixes; see `testbed/PROVENANCE.md`.

## Setup

Packaging uses [uv](https://docs.astral.sh/uv/). Python >= 3.10.

```bash
uv sync                       # build the env from pyproject.toml + uv.lock
```

Run any glue script through the environment:

```bash
uv run python treeshap/train_models.py
```

### Data

The dataset is TON-IoT: raw pcaps plus the official `GroundTruth_Network` CSVs
(Alsaedi et al., *IEEE Access* 2020). Point `paths.py` at it one of two ways:

- set `DUNE_FAIR_DATA` to the data root (and `DUNE_FAIR_GT` to the ground-truth CSV dir), or
- place the data under `./data`.

Stage 0 (`data_generation`, tshark) needs the raw pcaps. The offline pipeline from
`train_7class.csv` onward needs only the ML dependencies.

**Skip Stage 0.** The processed canonical dataset used for the published results
(`train_7class.csv`, `ToN_IoT_test.pcap`, and the `stage4/` inputs) is attached to the
GitHub Release. Download it into your data root and the pipeline runs from there. To rebuild
it from raw TON-IoT instead, run `treeshap/prepare_dataset.py` (a single, documented pass that
merges the captures). Regenerated data is equivalent, not byte-identical, to the Release.

## Running the offline pipeline

Each step writes artifacts the next step reads, so run them in order:

```bash
uv run python treeshap/build_label_map.py     # Flow ID -> Label
#   (run DUNE data_generation per pcap set to produce flow features)
uv run python treeshap/prepare_dataset.py     # train_7class.csv + test pcap + Stage-4 inputs (one-time)
uv run python treeshap/train_models.py        # Stage 1 + TreeSHAP
uv run python treeshap/build_importance.py    # Stage 2 importance matrices
uv run python treeshap/run_spp.py             # Stage 3 partition
uv run python treeshap/stage45.py             # Stage 4 grid + Stage 5 TSP
uv run python treeshap/collate.py             # results_comparison.csv
```

`collate.py` reads only persisted artifacts and prints the comparison table above.

## Stage 6: in-network deploy (lab only)

Stage 6 runs on a real BMv2 lab box and is **not pip-installable**. It needs the
[p4-guide](https://github.com/jafingerhut/p4-guide) toolchain: `simple_switch_grpc`,
Mininet, and `p4runtime_sh`.

```bash
uv run python treeshap/train_submodels.py rf                       # sub-models for one model
uv run python treeshap/generate_p4.py --sav <F.sav> --out <X.p4> \
    --model-id <N> --offset <K> --classlist "<c1,c2,...>"          # emit the P4 program
```

The `testbed/` then deploys the generated P4 and scores it against the test pcap.

## Honest caveats

- **TON-IoT port bias.** The dataset is testbed traffic; web-attack classes (xss, injection,
  password) concentrate on the victim's service ports, so port features inflate their
  separability beyond what a production capture would give.
- **"Normal" is not a clean benign capture.** It is background traffic absent from the attack
  ground truth, recovered from the DoS captures, not an independent benign trace.
- **Deployable feature set.** Stage 4 restricts features to the 19 BMv2-deployable ones. No
  division-based features (e.g. Flow IAT Mean, Packet Length Mean) reach the switch.
- **Statistical tie.** Results are mean ± std over ten seeds; the four models are
  statistically tied (pairwise Wilcoxon n.s.), so no single ensemble is reliably best.

## Citing

- DUNE — Akem et al., *DUNE: Distributing Inference in the Network*, IEEE INFOCOM 2025.
  Source: https://github.com/nds-group/DUNE
- TON-IoT — Alsaedi et al., *TON_IoT Telemetry Dataset*, IEEE Access, 2020.
