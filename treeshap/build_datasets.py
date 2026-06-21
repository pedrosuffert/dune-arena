"""
Build train + test datasets for DUNE TCC thesis.
Inputs:
  - ~/realbuild/slim_pcaps/hybrid_data/TON-IOT_test_4.csv  (6 classes: no dos)
  - ~/realbuild/dos_only/hybrid_data/TON-IOT_test_4.csv     (dos class, large)
  - ~/realbuild/slim_pcaps/{ddos,dos,normal,scanning,xss,password,injection}.pcap
  - ~/realbuild/dos_only/dos.pcap
Outputs:
  - ~/realbuild/output/train_7class.csv
  - ~/realbuild/output/ToN_IoT_test.pcap           (Ethernet-wrapped)
  - ~/realbuild/output/ToN_IoT_Flow_PktCounts.csv  (Flow ID,type,packet_counts)
"""
import pandas as pd
import numpy as np
import os, random
from pathlib import Path
import paths

random.seed(42)
np.random.seed(42)

FLOWS_PER_CLASS = 2000       # train flows per class
TEST_FLOWS_PER_CLASS = 500   # test flows per class (held-out)
MAX_PKTS_PER_FLOW = 100      # cap packets per test flow

SLIM_HYB = paths.SLIM / "hybrid_data" / "TON-IOT_test_4.csv"
DOS_HYB  = paths.DOS / "hybrid_data" / "TON-IOT_test_4.csv"
OUT      = paths.OUTPUT
OUT.mkdir(exist_ok=True)

# 1 ── load merged hybrid data
print("Loading slim hybrid...")
slim = pd.read_csv(SLIM_HYB, dtype=str)

print("Loading dos hybrid...")
dos_df = pd.read_csv(DOS_HYB, dtype=str)
dos_df = dos_df[dos_df["Label"]=="dos"]

# Drop old thin dos rows from slim, append new dos rows
slim = slim[slim["Label"]!="dos"]
df = pd.concat([slim, dos_df], ignore_index=True)

print("Label dist (rows):")
print(df["Label"].value_counts())
print("\nFlows per label:")
flow_counts = df.groupby("Label")["Flow ID"].nunique()
print(flow_counts)

# 2 ── flow-level 80/20 split per class
train_rows = []
test_flows_per_class = {}  # label -> set of flow IDs

for label, grp in df.groupby("Label"):
    flows = grp["Flow ID"].unique().tolist()
    random.shuffle(flows)
    n_test = min(TEST_FLOWS_PER_CLASS, max(1, len(flows)//5))
    n_train = min(FLOWS_PER_CLASS, len(flows) - n_test)
    test_flows = set(flows[:n_test])
    train_flows = set(flows[n_test:n_test+n_train])
    test_flows_per_class[label] = test_flows
    train_rows.append(grp[grp["Flow ID"].isin(train_flows)])
    print(f"{label}: {len(train_flows)} train flows, {len(test_flows)} test flows")

train_df = pd.concat(train_rows, ignore_index=True)
# Cast numeric cols back
str_cols = {"Flow ID", "Label", "File"}
for c in train_df.columns:
    if c not in str_cols:
        train_df[c] = pd.to_numeric(train_df[c], errors="coerce").fillna(0)

train_path = OUT/"train_7class.csv"
train_df.to_csv(train_path, index=False)
print(f"\nTrain saved: {train_path} ({len(train_df)} rows)")
print(train_df["Label"].value_counts())

# 3 ── build pcap + flow counts from test flows using scapy
print("\nBuilding test pcap...")
from scapy.all import rdpcap, wrpcap, Ether, IP, Raw, PcapWriter

# map: label -> source pcap path
PCAP_MAP = {
    "ddos":      str(paths.SLIM / "ddos.pcap"),
    "dos":       str(paths.DOS / "dos.pcap"),
    "injection": str(paths.SLIM / "injection.pcap"),
    "normal":    str(paths.SLIM / "normal.pcap"),
    "password":  str(paths.SLIM / "password.pcap"),
    "scanning":  str(paths.SLIM / "scanning.pcap"),
    "xss":       str(paths.SLIM / "xss.pcap"),
}

# Build set of all test flow IDs (to filter raw pcap packets)
all_test_flows = {}  # flow_id -> label
for label, fset in test_flows_per_class.items():
    for fid in fset:
        all_test_flows[fid] = label

# Flow ID format: "ip.src ip.dst srcport dstport proto_num"
def flow_id(pkt):
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    proto = ip.proto
    if proto == 6 and pkt.haslayer("TCP"):
        s, d = pkt["TCP"].sport, pkt["TCP"].dport
    elif proto == 17 and pkt.haslayer("UDP"):
        s, d = pkt["UDP"].sport, pkt["UDP"].dport
    else:
        return None
    return f"{ip.src} {ip.dst} {s} {d} {proto}"

def wrap_ethernet(pkt):
    """Strip any Ether/SLL layer, wrap in fresh Ethernet + IP."""
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02", type=0x0800) / ip
    return None

writer = PcapWriter(str(OUT/"ToN_IoT_test.pcap"), linktype=1, sync=True)
pkt_counts = {}  # flow_id -> count

for label, pcap_path in PCAP_MAP.items():
    target_flows = test_flows_per_class.get(label, set())
    if not target_flows:
        continue
    print(f"  Scanning {label} pcap for {len(target_flows)} test flows...")
    pkts_per_flow = {fid: 0 for fid in target_flows}
    try:
        for pkt in rdpcap(pcap_path):
            fid = flow_id(pkt)
            if fid not in pkts_per_flow:
                continue
            if pkts_per_flow[fid] >= MAX_PKTS_PER_FLOW:
                continue
            wrapped = wrap_ethernet(pkt)
            if wrapped is None:
                continue
            writer.write(wrapped)
            pkts_per_flow[fid] += 1
    except Exception as e:
        print(f"    WARNING: {e}")
    for fid, cnt in pkts_per_flow.items():
        if cnt > 0:
            pkt_counts[fid] = cnt
    print(f"    {label}: {sum(1 for v in pkts_per_flow.values() if v>0)} flows with pkts")

writer.close()

# 4 ── write Flow_PktCounts
rows = []
for fid, cnt in pkt_counts.items():
    label = all_test_flows.get(fid, "normal")
    rows.append({"Flow ID": fid, "type": label, "packet_counts": cnt})

gt_df = pd.DataFrame(rows)
gt_path = OUT/"ToN_IoT_Flow_PktCounts.csv"
gt_df.to_csv(gt_path, index=False)
print(f"\nFlow PktCounts saved: {gt_path} ({len(gt_df)} flows)")
print(gt_df["type"].value_counts())
print("DONE")
