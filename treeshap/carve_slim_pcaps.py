#!/usr/bin/env python3
"""Carve per-class pcaps from the raw TON-IoT captures (the reproducibility step).

This is the piece that lets anyone with the raw TON-IoT download rebuild the
dataset. It turns the large, mixed raw scenario captures into small, bounded,
per-class pcaps that DUNE's Stage-0 datagen consumes.

  - Attack classes: keep only that class's ground-truth flows (forward 5-tuples
    from ``attack_label_map.csv``) -> attack-only pcaps, no background.
  - normal: TON-IoT's GroundTruth lists only attacks, so 'normal' has no flow
    list. We sample flows from the dedicated benign captures (``normal_pcaps``),
    giving a clean benign class instead of attack-capture background.

Run order:
    python build_label_map.py      # -> attack_label_map.csv
    python carve_slim_pcaps.py     # -> slim_pcaps/*.pcap + dos_only/dos.pcap
    # then DUNE Stage-0 datagen (data_path=slim_pcaps, then data_path=dos_only)
    python prepare_dataset.py

Paths come from ``paths.py`` (env ``DUNE_FAIR_RAW`` for the raw capture root).

Streams with scapy for simple, dependency-light code; a one-time full run over the
raw captures takes a while (tens of GB) -- run it in the background. For a quick
check use --classes/--max-files/--max-flows.
"""
import argparse
import sys
from collections import defaultdict

import pandas as pd
from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP

import paths

# class -> raw scenario subdir under paths.RAW. dos -> dos_only/, the rest -> slim_pcaps/.
SCENARIO = {
    "ddos":      "normal_attack_pcaps/normal_DDoS",
    "dos":       "normal_attack_pcaps/normal_DoS",
    "injection": "normal_attack_pcaps/Injection_normal",
    "password":  "normal_attack_pcaps/password_normal",
    "scanning":  "normal_attack_pcaps/normal_scanning",
    "xss":       "normal_attack_pcaps/normal_XSS",
}
NORMAL_SUBDIR = "normal_pcaps"
ALL_CLASSES = list(SCENARIO) + ["normal"]

DEFAULT_MAX_FLOWS = 3000      # per class; > 2500 needed (2000 train + 500 test)
DEFAULT_MAX_PKTS = 100        # packets kept per flow


def flow_id(ip):
    """Forward 5-tuple 'src dst sport dport proto' matching attack_label_map / datagen."""
    if TCP in ip:
        l4, proto = ip[TCP], 6
    elif UDP in ip:
        l4, proto = ip[UDP], 17
    else:
        return None
    return f"{ip.src} {ip.dst} {l4.sport} {l4.dport} {proto}"


def out_path(cls):
    return (paths.DOS / "dos.pcap") if cls == "dos" else (paths.SLIM / f"{cls}.pcap")


def raw_files(cls, max_files):
    subdir = NORMAL_SUBDIR if cls == "normal" else SCENARIO[cls]
    files = sorted((paths.RAW / subdir).glob("*.pcap"))
    return files[:max_files] if max_files else files


def load_targets(cls):
    """(target, exclude) flow-id sets. Attacks: keep only that class's GT flows.
    normal: accept any flow EXCEPT known attack fids -- TON-IoT reuses the same
    IP/port space across captures, so a benign-capture 5-tuple can collide with
    an attack entry in the label map and datagen would mislabel it."""
    df = pd.read_csv(paths.LABEL_MAP, usecols=["Flow ID", "Label"])
    if cls == "normal":
        return None, set(df["Flow ID"])
    return set(df.loc[df["Label"] == cls, "Flow ID"]), None


def carve(cls, max_flows, max_pkts, max_files):
    target, exclude = load_targets(cls)
    out = out_path(cls)
    out.parent.mkdir(parents=True, exist_ok=True)
    files = raw_files(cls, max_files)
    if not files:
        print(f"  !! no raw pcaps for {cls} under {paths.RAW}", file=sys.stderr)
        return 0, 0

    seen = defaultdict(int)     # flow_id -> packets written so far
    satisfied = 0               # accepted flows that reached max_pkts
    written = 0
    idle = 0                    # packets skipped in a row while the flow budget is full
    IDLE_STOP = 500_000         # ponytail: once full, this many no-op packets => accepted flows exhausted
    note = ""
    writer = PcapWriter(str(out), sync=True)
    for f in files:
        broke = False
        with PcapReader(str(f)) as rd:
            for pkt in rd:
                if IP not in pkt:
                    continue
                ip = pkt[IP]
                if ip.src == ip.dst or ip.src.startswith("127.") or ip.dst.startswith("127."):
                    continue                        # skip loopback / same-host (never crosses a switch)
                fid = flow_id(ip)
                if fid is None:
                    continue
                if target is not None and fid not in target:
                    continue
                if exclude is not None and fid in exclude:
                    continue
                full = len(seen) >= max_flows
                if (fid in seen or not full) and seen[fid] < max_pkts:
                    writer.write(pkt)
                    seen[fid] += 1
                    written += 1
                    idle = 0
                    if seen[fid] == max_pkts:
                        satisfied += 1
                elif full:
                    idle += 1
                # done once every wanted flow is full, or the budget is full and nothing
                # new is being collected (short-flow classes never reach max_pkts)
                if full and (satisfied >= max_flows or idle > IDLE_STOP):
                    note = " (early stop)"
                    broke = True
                    break
        if broke:
            break
    writer.close()
    print(f"  {cls}: {len(seen)} flows, {written} pkts{note}")
    return len(seen), written


def main():
    ap = argparse.ArgumentParser(description="Carve per-class pcaps from raw TON-IoT.")
    ap.add_argument("--classes", default=",".join(ALL_CLASSES),
                    help="comma list (default: all), e.g. xss,normal")
    ap.add_argument("--max-flows", type=int, default=DEFAULT_MAX_FLOWS)
    ap.add_argument("--max-pkts", type=int, default=DEFAULT_MAX_PKTS)
    ap.add_argument("--max-files", type=int, default=0,
                    help="limit raw files scanned per class (0=all; small N to smoke-test)")
    args = ap.parse_args()

    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    bad = [c for c in classes if c not in ALL_CLASSES]
    if bad:
        sys.exit(f"unknown classes: {bad}; valid: {ALL_CLASSES}")

    print(f"RAW={paths.RAW}\nSLIM={paths.SLIM}  DOS={paths.DOS}")
    print(f"classes={classes} max_flows={args.max_flows} max_pkts={args.max_pkts} "
          f"max_files={args.max_files or 'all'}\n")
    for cls in classes:
        src = NORMAL_SUBDIR if cls == "normal" else SCENARIO[cls]
        print(f"Carving {cls} from {src} ...")
        carve(cls, args.max_flows, args.max_pkts, args.max_files)
    print("DONE")


if __name__ == "__main__":
    main()
