"""Single source of truth for filesystem paths.

Override the data location with env DUNE_FAIR_DATA (default: <repo>/data).
Ground-truth CSV dir via env DUNE_FAIR_GT. Nothing else hardcodes a path.
"""
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]                 # the fork repo root
DATA = Path(os.environ.get("DUNE_FAIR_DATA", ROOT / "data"))

OUTPUT    = DATA / "output"
MODELS    = DATA / "models"
STAGE4    = DATA / "stage4"
SLIM      = DATA / "slim_pcaps"
DOS       = DATA / "dos_only"
LABEL_MAP = DATA / "attack_label_map.csv"
TRAIN_CSV = OUTPUT / "train_7class.csv"
GT_DIR = Path(os.environ.get(
    "DUNE_FAIR_GT",
    Path.home() / "TON_IoT" / "SecuityEvents_GroundTruth_datasets" / "SecurityEvents_Network_datasets"))
RAW = Path(os.environ.get(
    "DUNE_FAIR_RAW",
    Path.home() / "TON_IoT" / "Raw_datasets" / "network_data" / "Network_dataset_pcaps"))

SPP_SOLVER = ROOT / "model_partitioning" / "src"           # DUNE SPP package lives here now


def _set(ini: Path, key: str, val) -> None:
    txt = ini.read_text()
    txt = re.sub(rf"(?m)^{re.escape(key)} = .*$", f"{key} = {val}", txt)
    ini.write_text(txt)


def stamp_stage4(model: str) -> None:
    """Point DUNE's cluster_analysis params.ini at this repo's data for one model."""
    ini = ROOT / "cluster_analysis" / "src" / "params.ini"
    _set(ini, "train_data_dir_path", STAGE4)
    _set(ini, "test_data_dir_path", STAGE4)
    _set(ini, "flow_counts_test_file_path", STAGE4 / "flow_counts_test.csv")
    _set(ini, "flow_counts_train_file_path", STAGE4 / "flow_counts_all.csv")
    _set(ini, "cluster_data_file_path", MODELS / model / "spp_4cluster.csv")
    _set(ini, "results_dir_path", MODELS / model / "stage4_results")


def stamp_stage5(model: str) -> None:
    """Point DUNE's model_sequencing params.ini at this repo's data for one model."""
    ini = ROOT / "model_sequencing" / "src" / "params.ini"
    _set(ini, "train_data_dir_path", STAGE4)
    _set(ini, "test_data_dir_path", STAGE4)
    _set(ini, "flow_counts_test_file_path", STAGE4 / "flow_counts_test.csv")
    _set(ini, "flow_counts_train_file_path", STAGE4 / "flow_counts_all.csv")
    _set(ini, "best_models_per_cluster_path",
         MODELS / model / "stage4_results" / "perf_results" / "cluster_info_df.csv")
    _set(ini, "results_dir_path", MODELS / model / "stage5_results")


if __name__ == "__main__":
    print(f"ROOT={ROOT}\nDATA={DATA}\nGT_DIR={GT_DIR}")
