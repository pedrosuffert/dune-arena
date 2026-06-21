#!/usr/bin/env python3
"""Build attack Flow ID -> Label map from ToN_IoT official GroundTruth_Network CSVs.

Flow ID format matches DUNE: "ip.src ip.dst srcport dstport ip.proto" (proto as number).
GroundTruth columns: ts,src_ip,src_port,dst_ip,dst_port,proto,type
Keeps only the chosen DoS-focused class set. Normal is added later (background flows).
"""
import csv
import glob
import os
from collections import Counter
import paths

GT_DIR = str(paths.GT_DIR)
KEEP = {"ddos", "dos", "scanning", "xss", "password", "injection"}
PROTO = {"tcp": "6", "udp": "17"}
OUT = str(paths.LABEL_MAP)

flow_label = {}
collisions = 0
seen_types = Counter()
for path in sorted(glob.glob(os.path.join(GT_DIR, "GroundTruth_Network_*.csv"))):
    with open(path, newline="") as f:
        r = csv.reader(f)
        header = next(r, None)
        for row in r:
            if len(row) < 7:
                continue
            ts, src_ip, src_port, dst_ip, dst_port, proto, typ = row[:7]
            typ = typ.strip()
            if typ not in KEEP:
                continue
            pn = PROTO.get(proto.strip().lower())
            if pn is None:
                continue
            fid = f"{src_ip} {dst_ip} {src_port} {dst_port} {pn}"
            if fid in flow_label and flow_label[fid] != typ:
                collisions += 1
            flow_label[fid] = typ
            seen_types[typ] += 1

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["Flow ID", "Label"])
    for fid, lab in flow_label.items():
        w.writerow([fid, lab])

print(f"rows seen per type: {dict(seen_types)}")
print(f"unique flow IDs written: {len(flow_label)}  (label collisions: {collisions})")
# distinct flow IDs per label after dedup
final = Counter(flow_label.values())
print(f"unique flows per label: {dict(final)}")
print(f"wrote {OUT}")
