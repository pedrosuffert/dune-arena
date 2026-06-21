"""
Patch: add 'normal' class to test pcap + Flow_PktCounts.
Normal flows come from dos_only hybrid (background in dos.pcap).
Avoids flow IDs already used in train set.
"""
import pandas as pd, numpy as np, random
from pathlib import Path
from scapy.all import rdpcap, PcapWriter, Ether, IP
import paths

random.seed(42)

TRAIN_CSV   = paths.TRAIN_CSV
DOS_HYB     = paths.DOS / "hybrid_data" / "TON-IOT_test_4.csv"
DOS_PCAP    = str(paths.DOS / "dos.pcap")
OUT_PCAP    = paths.OUTPUT / "ToN_IoT_test.pcap"
OUT_GT      = paths.OUTPUT / "ToN_IoT_Flow_PktCounts.csv"
MAX_PKTS    = 100
TEST_FLOWS  = 500

# flow IDs already in train
train_flows = set(pd.read_csv(TRAIN_CSV, usecols=["Flow ID"])["Flow ID"])

# normal flow IDs from dos_only hybrid, not in train
dos_hyb = pd.read_csv(DOS_HYB, usecols=["Flow ID","Label"])
norm_flows = dos_hyb[dos_hyb["Label"]=="normal"]["Flow ID"].unique().tolist()
norm_flows = [f for f in norm_flows if f not in train_flows]
random.shuffle(norm_flows)
target = set(norm_flows[:TEST_FLOWS])
print(f"Target normal test flows: {len(target)}")

def flow_id(pkt):
    if not pkt.haslayer(IP): return None
    ip = pkt[IP]
    proto = ip.proto
    if proto == 6 and pkt.haslayer("TCP"):
        s, d = pkt["TCP"].sport, pkt["TCP"].dport
    elif proto == 17 and pkt.haslayer("UDP"):
        s, d = pkt["UDP"].sport, pkt["UDP"].dport
    else:
        return None
    return f"{ip.src} {ip.dst} {s} {d} {proto}"

def wrap(pkt):
    if pkt.haslayer(IP):
        return Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02", type=0x0800)/pkt[IP]
    return None

pkts_per_flow = {f: 0 for f in target}
writer = PcapWriter(str(OUT_PCAP), linktype=1, append=True, sync=True)
print("Scanning dos.pcap...")
for pkt in rdpcap(DOS_PCAP):
    fid = flow_id(pkt)
    if fid not in pkts_per_flow: continue
    if pkts_per_flow[fid] >= MAX_PKTS: continue
    w = wrap(pkt)
    if w: writer.write(w); pkts_per_flow[fid] += 1
writer.close()

found = {f: c for f,c in pkts_per_flow.items() if c > 0}
print(f"Normal flows with packets: {len(found)}")

# append to GT csv
gt = pd.read_csv(OUT_GT)
new_rows = pd.DataFrame([{"Flow ID": f, "type": "normal", "packet_counts": c}
                          for f,c in found.items()])
gt = pd.concat([gt, new_rows], ignore_index=True)
gt.to_csv(OUT_GT, index=False)
print(f"Updated GT: {len(gt)} flows")
print(gt["type"].value_counts())
print("DONE")
