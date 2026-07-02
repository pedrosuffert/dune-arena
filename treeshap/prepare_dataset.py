"""One-time assembly of the canonical 7-class TON-IoT dataset for this thesis.

Run ONCE. The multi-seed experiment never calls this; it consumes the frozen
outputs (``output/train_7class.csv`` and ``stage4/``) and replays the frozen
``output/ToN_IoT_test.pcap``. Those artifacts are published as a GitHub Release;
this script documents how they were built and lets anyone with the raw TON-IoT
captures regenerate them.

Inputs are produced by ``carve_slim_pcaps.py`` (run after ``build_label_map.py``):

* ``slim_pcaps/``  - the six non-dos classes (ddos, scanning, xss, password,
  injection) plus a clean ``normal.pcap`` carved from TON-IoT's dedicated benign
  captures (``normal_pcaps``).
* ``dos_only/``    - the ``dos`` capture, kept apart only because it is large.

``dos`` rows come from ``dos_only``; ``normal`` is a genuine benign class carved
from ``normal.pcap`` (not attack-capture background). DUNE's Stage-0 datagen turns
these per-class pcaps into the hybrid feature CSVs read below; the merged output is
a single, uniform 7-class dataset.

Outputs (under ``paths.OUTPUT`` and ``paths.STAGE4``)
  output/train_7class.csv            - per-flow training rows, 7 classes
  output/ToN_IoT_test.pcap           - held-out test flows, Ethernet-wrapped
  output/ToN_IoT_Flow_PktCounts.csv  - test ground truth (Flow ID, type, count)
  stage4/{flow_counts_all,train_4_pkts,test_4_pkts,flow_counts_test}.csv
"""
import random
import numpy as np
import pandas as pd
from scapy.all import rdpcap, PcapWriter, Ether, IP
import paths

FLOWS_PER_CLASS = 2000        # train flows per class
TEST_FLOWS_PER_CLASS = 500    # held-out test flows per class
MAX_PKTS_PER_FLOW = 100       # cap packets per test flow

SLIM_HYB = paths.SLIM / "hybrid_data" / "TON-IOT_test_4.csv"
DOS_HYB = paths.DOS / "hybrid_data" / "TON-IOT_test_4.csv"


# ── shared helpers ──────────────────────────────────────────────────────────
def flow_id(pkt):
    """5-tuple key 'ip.src ip.dst sport dport proto' (TCP/UDP only)."""
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
    """Strip any link layer, wrap the IP payload in a fresh Ethernet header."""
    if pkt.haslayer(IP):
        return Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02", type=0x0800) / pkt[IP]
    return None


# ── step 1: merge hybrids, flow-split, build train CSV + test pcap + GT ───────
def build_train_and_test():
    random.seed(42)
    np.random.seed(42)
    out = paths.OUTPUT
    out.mkdir(exist_ok=True)

    print("Loading slim hybrid...")
    slim = pd.read_csv(SLIM_HYB, dtype=str)
    print("Loading dos hybrid...")
    dos_df = pd.read_csv(DOS_HYB, dtype=str)
    dos_df = dos_df[dos_df["Label"] == "dos"]

    # drop any thin slim dos rows, splice in the real dos rows
    slim = slim[slim["Label"] != "dos"]
    df = pd.concat([slim, dos_df], ignore_index=True)
    print("Label dist (rows):")
    print(df["Label"].value_counts())
    print("\nFlows per label:")
    print(df.groupby("Label")["Flow ID"].nunique())

    # flow-level 80/20 split per class
    train_rows = []
    test_flows_per_class = {}
    for label, grp in df.groupby("Label"):
        flows = grp["Flow ID"].unique().tolist()
        random.shuffle(flows)
        n_test = min(TEST_FLOWS_PER_CLASS, max(1, len(flows) // 5))
        n_train = min(FLOWS_PER_CLASS, len(flows) - n_test)
        test_flows = set(flows[:n_test])
        train_flows = set(flows[n_test:n_test + n_train])
        test_flows_per_class[label] = test_flows
        train_rows.append(grp[grp["Flow ID"].isin(train_flows)])
        print(f"{label}: {len(train_flows)} train flows, {len(test_flows)} test flows")

    train_df = pd.concat(train_rows, ignore_index=True)
    str_cols = {"Flow ID", "Label", "File"}
    for c in train_df.columns:
        if c not in str_cols:
            train_df[c] = pd.to_numeric(train_df[c], errors="coerce").fillna(0)
    train_path = out / "train_7class.csv"
    train_df.to_csv(train_path, index=False)
    print(f"\nTrain saved: {train_path} ({len(train_df)} rows)")
    print(train_df["Label"].value_counts())

    # build test pcap + packet counts from the held-out flows
    print("\nBuilding test pcap...")
    pcap_map = {
        "ddos": str(paths.SLIM / "ddos.pcap"),
        "dos": str(paths.DOS / "dos.pcap"),
        "injection": str(paths.SLIM / "injection.pcap"),
        "normal": str(paths.SLIM / "normal.pcap"),
        "password": str(paths.SLIM / "password.pcap"),
        "scanning": str(paths.SLIM / "scanning.pcap"),
        "xss": str(paths.SLIM / "xss.pcap"),
    }
    all_test_flows = {}
    for label, fset in test_flows_per_class.items():
        for fid in fset:
            all_test_flows[fid] = label

    writer = PcapWriter(str(out / "ToN_IoT_test.pcap"), linktype=1, sync=True)
    pkt_counts = {}
    for label, pcap_path in pcap_map.items():
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
        print(f"    {label}: {sum(1 for v in pkts_per_flow.values() if v > 0)} flows with pkts")
    writer.close()

    rows = [{"Flow ID": fid, "type": all_test_flows.get(fid, "normal"), "packet_counts": cnt}
            for fid, cnt in pkt_counts.items()]
    gt_df = pd.DataFrame(rows)
    gt_path = out / "ToN_IoT_Flow_PktCounts.csv"
    gt_df.to_csv(gt_path, index=False)
    print(f"\nFlow PktCounts saved: {gt_path} ({len(gt_df)} flows)")
    print(gt_df["type"].value_counts())


# ── step 2: build DUNE Stage-4 inputs (train/test hybrids + flow counts, N=4) ─
def build_stage4_inputs():
    rb = paths.DATA
    out = rb / "stage4"
    out.mkdir(exist_ok=True)
    gt = pd.read_csv(rb / "output/ToN_IoT_Flow_PktCounts.csv")
    test_flows = set(gt["Flow ID"])

    fl = [pd.read_csv(p, usecols=["Flow ID", "count"]) for p in
          [rb / "slim_pcaps/TON-IOT_flow_length.csv", rb / "dos_only/TON-IOT_flow_length.csv"]]
    flc = pd.concat(fl, ignore_index=True).groupby("Flow ID", as_index=False)["count"].max()
    flc = flc.rename(columns={"count": "packet_counts"})
    flc.to_csv(out / "flow_counts_all.csv", index=False)
    print(f"flow_counts_all: {len(flc)} flows")

    tr = pd.read_csv(rb / "output/train_7class.csv")
    if "File" in tr.columns:
        tr = tr.drop(columns=["File"])
    tr.to_csv(out / "train_4_pkts.csv", index=False)
    train_cov = tr["Flow ID"].isin(set(flc["Flow ID"])).mean()
    print(f"train_4_pkts: {len(tr)} rows, {tr['Flow ID'].nunique()} flows, count-coverage={train_cov:.3f}")

    hyb = [pd.read_csv(p) for p in
           [rb / "slim_pcaps/hybrid_data/TON-IOT_test_4.csv", rb / "dos_only/hybrid_data/TON-IOT_test_4.csv"]]
    H = pd.concat(hyb, ignore_index=True)
    if "File" in H.columns:
        H = H.drop(columns=["File"])
    te = H[H["Flow ID"].isin(test_flows)].copy().drop_duplicates()
    te.to_csv(out / "test_4_pkts.csv", index=False)
    print(f"test_4_pkts: {len(te)} rows, {te['Flow ID'].nunique()} flows (GT has {len(test_flows)})")
    print("test label dist:\n", te["Label"].value_counts())

    gt[["Flow ID", "type", "packet_counts"]].to_csv(out / "flow_counts_test.csv", index=False)
    print("DONE")


def main():
    build_train_and_test()
    build_stage4_inputs()


if __name__ == "__main__":
    main()
