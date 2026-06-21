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

## Results (offline, Stages 1–5)

Flow-weighted macro-F1 over the seven classes, DUNE TCAM cost, and the Stage-5 cluster
sequence. Higher F1 is better; lower TCAM is cheaper.

| Stage-1 model | macro-F1 | TCAM | sequence | class partition |
|---------------|---------:|-----:|----------|-----------------|
| RF       | 89.91 | 10.76 | `[2,3,1,0]` | `{ddos} {injection} {dos,normal,password,scanning} {xss}` |
| LightGBM | 89.60 |  8.33 | `[3,2,1,0]` | `{ddos} {injection} {dos,normal,password,scanning} {xss}` |
| CatBoost | 89.50 | 10.76 | `[2,1,3,0]` | `{ddos} {injection} {dos,normal,password,scanning} {xss}` |
| XGBoost  | 89.19 |  5.56 | `[2,1,3,0]` | `{dos} {normal} {scanning} {ddos,injection,password,xss}` |

RF, LightGBM, and CatBoost reach the *same* class partition yet deploy *different* sub-models:
each ranks features by its own TreeSHAP and lands on different tree configurations. That
divergence is the propagation fix working. XGBoost is the outlier: it does not isolate `ddos`,
buys the cheapest TCAM, and scores the lowest macro-F1. A model-dependent accuracy/cost
tradeoff now reaches hardware, which the released pipeline could not express.

**In-network (real BMv2 fattree, 7 classes, 3258 flows).** Each pipeline was deployed and
scored end to end. The Stage-1 choice propagates: the four deploy distinctly and score
distinctly.

| Stage-1 model | offline macro-F1 | in-network macro-F1 | gap |
|---------------|-----------------:|--------------------:|----:|
| RF       | 89.91 | 89.66 | -0.25% |
| LightGBM | 89.60 | 89.24 | -0.36% |
| XGBoost  | 89.19 | 88.59 | -0.60% |
| CatBoost | 89.50 | 87.77 | -1.73% |

In-network tracks offline within 1.8% for every model, so the generated P4 is faithful to the
trained sub-models. CatBoost degrades most on hardware; the in-network ranking is
RF > LightGBM > XGBoost > CatBoost.

## Repository layout

```
dune-arena/
├── treeshap/                 # contribution layer: the pipeline glue
│   ├── paths.py              #   single path source; env DUNE_FAIR_DATA / DUNE_FAIR_GT override
│   ├── build_label_map.py    #   Flow ID -> Label map from TON-IoT GroundTruth CSVs
│   ├── build_datasets.py     #   train_7class.csv + Ethernet-wrapped test pcap
│   ├── patch_normal_test.py  #   add the 'normal' (background) class to the test set
│   ├── prep_stage4.py        #   build DUNE Stage-4 inputs at N=4 clusters
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

## Running the offline pipeline

Each step writes artifacts the next step reads, so run them in order:

```bash
uv run python treeshap/build_label_map.py     # Flow ID -> Label
#   (run DUNE data_generation per pcap set to produce flow features)
uv run python treeshap/build_datasets.py      # train_7class.csv + test pcap
uv run python treeshap/patch_normal_test.py   # add 'normal' to the test set
uv run python treeshap/prep_stage4.py         # Stage-4 inputs
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
- **Single seed.** Every result above comes from one random seed; no variance is reported.

## Citing

- DUNE — Akem et al., *DUNE: Distributing Inference in the Network*, IEEE INFOCOM 2025.
  Source: https://github.com/nds-group/DUNE
- TON-IoT — Alsaedi et al., *TON_IoT Telemetry Dataset*, IEEE Access, 2020.
