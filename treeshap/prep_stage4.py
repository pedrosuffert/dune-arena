"""Build DUNE Stage-4 inputs (train/test hybrid CSVs + flow counts) at N=4."""
import pandas as pd
from pathlib import Path
import paths

RB = paths.DATA
OUT = RB/"stage4"; OUT.mkdir(exist_ok=True)
GT = pd.read_csv(RB/"output/ToN_IoT_Flow_PktCounts.csv")   # Flow ID,type,packet_counts
test_flows = set(GT["Flow ID"])

# 1 ── flow_counts_all (Flow ID -> packet_counts), from flow_length files
fl = []
for p in [RB/"slim_pcaps/TON-IOT_flow_length.csv", RB/"dos_only/TON-IOT_flow_length.csv"]:
    d = pd.read_csv(p, usecols=["Flow ID","count"])
    fl.append(d)
flc = pd.concat(fl, ignore_index=True).groupby("Flow ID", as_index=False)["count"].max()
flc = flc.rename(columns={"count":"packet_counts"})
flc.to_csv(OUT/"flow_counts_all.csv", index=False)
print(f"flow_counts_all: {len(flc)} flows")

# 2 ── train_4_pkts.csv = train_7class.csv minus File (plain Flow ID)
tr = pd.read_csv(RB/"output/train_7class.csv")
if "File" in tr.columns: tr = tr.drop(columns=["File"])
tr.to_csv(OUT/"train_4_pkts.csv", index=False)
train_cov = tr["Flow ID"].isin(set(flc["Flow ID"])).mean()
print(f"train_4_pkts: {len(tr)} rows, {tr['Flow ID'].nunique()} flows, count-coverage={train_cov:.3f}")

# 3 ── test_4_pkts.csv = merged hybrid rows for held-out test flows
hyb = []
for p in [RB/"slim_pcaps/hybrid_data/TON-IOT_test_4.csv", RB/"dos_only/hybrid_data/TON-IOT_test_4.csv"]:
    hyb.append(pd.read_csv(p))
H = pd.concat(hyb, ignore_index=True)
if "File" in H.columns: H = H.drop(columns=["File"])
te = H[H["Flow ID"].isin(test_flows)].copy()
# de-dup identical rows (a flow ID may appear in both hybrids)
te = te.drop_duplicates()
te.to_csv(OUT/"test_4_pkts.csv", index=False)
test_cov = te["Flow ID"].isin(set(GT["Flow ID"])).mean()
print(f"test_4_pkts: {len(te)} rows, {te['Flow ID'].nunique()} flows (GT has {len(test_flows)})")
print("test label dist:\n", te["Label"].value_counts())

# 4 ── flow_counts_test already = GT (Flow ID,packet_counts present)
GT[["Flow ID","type","packet_counts"]].to_csv(OUT/"flow_counts_test.csv", index=False)
print("DONE")
