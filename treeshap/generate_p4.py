"""
Stage 6b: DUNE-style bmv2 .p4 generator for an RF sub-model.
Emits a per-cluster InferenceModel program in DUNE's exact structure
(templated off ton_iot_m2.p4 / ton_iot_m4.p4), so DUNE's
convert_RF_and_populate_tables.py fills the entries and the existing
DUNE-bmv2 testbed runs it unchanged.

Usage:
  generate_p4.py --sav F.sav --out X.p4 --model-id N --offset K \
                 --classlist "injection,normal,password,xss" [--inference-point 4]
"""
import argparse, joblib
import numpy as np, pandas as pd

# ---------- width computation: copied verbatim from convert_RF_and_populate_tables.py ----------
def get_splits(forest, feature_names):
    data = []
    for t in range(len(forest.estimators_)):
        clf = forest[t]
        n_nodes = clf.tree_.node_count
        features = [feature_names[i] if i >= 0 else None for i in clf.tree_.feature]
        for i in range(0, n_nodes):
            threshold = clf.tree_.threshold[i]
            if threshold != -2.0:
                data.append([t, i, clf.tree_.children_left[i], clf.tree_.children_right[i],
                             threshold, features[i]])
    data = pd.DataFrame(data, columns=["Tree","NodeID","LeftID","RightID","Threshold","Feature"])
    return data

def get_feature_table(splits_data, feature_name):
    fd = splits_data[splits_data["Feature"] == feature_name].sort_values(by="Threshold").reset_index(drop=True)
    fd["Threshold"] = fd["Threshold"].astype(int)
    code = pd.DataFrame(); code["Threshold"] = fd["Threshold"]
    for tree_id, node in zip(list(fd["Tree"]), list(fd["NodeID"])):
        colname = "s" + str(tree_id) + "_" + str(node)
        thr = fd[(fd["NodeID"]==node) & (fd["Tree"]==tree_id)]["Threshold"].values[0]
        code[colname] = np.where(code["Threshold"] <= thr, 0, 1)
    if len(code) > 0:
        temp = [max(code["Threshold"]) + 1]; temp.extend(list([1]*(len(code.columns)-1)))
        code.loc[len(code)] = temp
        code = code.drop_duplicates(subset=["Threshold"]).reset_index(drop=True)
    return code

def code_width_per_tree(clf, feats):
    """Returns widths[feature_index][tree_index] = bit width of that feature's code in that tree.
    Matches convert script's tree_code_sizes exactly (len('0b'+code)-2 == #split-columns of that tree)."""
    splits = get_splits(clf, feats)
    ntrees = len(clf.estimators_)
    widths = [[0]*ntrees for _ in feats]
    for fi, fname in enumerate(feats):
        ft = get_feature_table(splits, fname)
        for t in range(ntrees):
            cols = [c for c in ft.columns if c.startswith("s"+str(t)+"_")]
            widths[fi][t] = len(cols)   # one bit per split-node of this feature in tree t
    return widths

# ---------- feature -> P4 mapping ----------
# direct: usable straight in a table key (always present for IP), no Features_t, no guard
DIRECT = {
    "ip.len":  ("hdr.ipv4.total_length", 16),
    "ip.ttl":  ("hdr.ipv4.ttl", 8),
    "ip.hdr_len": ("hdr.ipv4.ihl", 4),
    "srcport": ("meta.src_port", 16),
    "dstport": ("meta.dst_port", 16),
}
# guarded packet: need Features_t field + TCP/UDP-guarded extraction
GUARDED = {  # name: (field, width, proto, src_expr)
    "udp.length":            ("udp_len", 16, "UDP", "hdr.udp.length"),
    "tcp.window_size_value": ("tcp_window", 16, "TCP", "hdr.tcp.window"),
    "tcp.hdr_len":           ("tcp_len", 4, "TCP", "hdr.tcp.data_offset"),
    "tcp.flags.syn":         ("tcp_syn", 1, "TCP", "hdr.tcp.syn"),
    "tcp.flags.ack":         ("tcp_ack", 1, "TCP", "hdr.tcp.ack"),
    "tcp.flags.push":        ("tcp_psh", 1, "TCP", "hdr.tcp.psh"),
    "tcp.flags.fin":         ("tcp_fin", 1, "TCP", "hdr.tcp.fin"),
    "tcp.flags.reset":       ("tcp_rst", 1, "TCP", "hdr.tcp.rst"),
}
# stateful: statefull_features.X + a GetUpdate action (library from stock + new SYN)
STATEFUL = {  # name: (field, width, action_name, action_body)
    "Packet Length Total": ("total_length", 16, "GetUpdateTotalLength",
        "        if (new_flow) {{ {f} = 0; }} else {{ flows_{f}.read({f}, hashes.reg_idx32); }}\n"
        "        {f} += hdr.ipv4.total_length;\n        flows_{f}.write(hashes.reg_idx32, {f});"),
    "Max Packet Length": ("max_length", 16, "GetUpdateMaxLength",
        "        flows_{f}.read({f}, hashes.reg_idx32);\n"
        "        if (new_flow || {f} < hdr.ipv4.total_length) {{ {f} = hdr.ipv4.total_length; flows_{f}.write(hashes.reg_idx32, {f}); }}"),
    "Min Packet Length": ("min_length", 16, "GetUpdateMinLength",
        "        flows_{f}.read({f}, hashes.reg_idx32);\n"
        "        if (new_flow || {f} > hdr.ipv4.total_length) {{ {f} = hdr.ipv4.total_length; flows_{f}.write(hashes.reg_idx32, {f}); }}"),
    "PSH Flag Count": ("psh_flag_count", 8, "GetUpdatePSHFlagCount",
        "        flows_{f}.read({f}, hashes.reg_idx32);\n"
        "        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.psh == 1) {{ {f} = {f} + 1; flows_{f}.write(hashes.reg_idx32, {f}); }}"),
    "ACK Flag Count": ("ack_flag_count", 8, "GetUpdateACKFlagCount",
        "        flows_{f}.read({f}, hashes.reg_idx32);\n"
        "        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.ack == 1) {{ {f} = {f} + 1; flows_{f}.write(hashes.reg_idx32, {f}); }}"),
    "SYN Flag Count": ("syn_flag_count", 8, "GetUpdateSYNFlagCount",
        "        flows_{f}.read({f}, hashes.reg_idx32);\n"
        "        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.syn == 1) {{ {f} = {f} + 1; flows_{f}.write(hashes.reg_idx32, {f}); }}"),
}
STATE_WIDTH = {"total_length":16,"max_length":16,"min_length":16,
               "psh_flag_count":8,"ack_flag_count":8,"syn_flag_count":8}

def keysrc(name):
    if name in DIRECT:   return DIRECT[name][0]
    if name in GUARDED:  return "features." + GUARDED[name][0]
    if name in STATEFUL: return "statefull_features." + STATEFUL[name][0]
    raise ValueError(f"unmapped feature: {name}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sav", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--model-id", type=int, required=True)
    ap.add_argument("--offset", type=int, required=True)
    ap.add_argument("--classlist", required=True)   # comma sep real classes in Class-List order
    ap.add_argument("--inference-point", type=int, default=4)
    a = ap.parse_args()

    clf = joblib.load(a.sav)
    feats = list(clf.feature_names_in_)
    ntrees = len(clf.estimators_)
    n_real = len(a.classlist.split(","))
    threshold = a.offset + n_real + 1
    widths = code_width_per_tree(clf, feats)
    for fi,row in enumerate(widths):              # guard against bit<0>
        for t,w in enumerate(row):
            if w == 0: widths[fi][t] = 1

    used_state = [f for f in feats if f in STATEFUL]
    if not used_state: used_state = ["Packet Length Total"]   # filler to avoid empty struct
    used_guard = [f for f in feats if f in GUARDED]
    L = []
    P = L.append
    P("#include <core.p4>")
    P("#include <v1model.p4>")
    P('#include "dune_headers.p4"\n')

    # ----- StatefullFeatures_t -----
    P("struct StatefullFeatures_t {")
    for f in used_state:
        fld = STATEFUL[f][0]; P(f"    bit<{STATE_WIDTH[fld]}> {fld};")
    P("}\n")

    # ----- UpdateAndGetStatefullFeatures -----
    P("control UpdateAndGetStatefullFeatures(")
    P("    in Headers_t hdr, in standard_metadata_t std_meta, in Hash_t hashes,")
    P("    in PktCount_t pkt_count, in bool new_flow, out StatefullFeatures_t statefull_features) {")
    for f in used_state:
        fld, w, act, body = STATEFUL[f][0], STATE_WIDTH[STATEFUL[f][0]], STATEFUL[f][2], STATEFUL[f][3]
        P(f"    bit<{w}> {fld};")
        P(f"    register<bit<{w}>>(NB_REG_ENTRIES) flows_{fld};")
        P(f"    action {act} () {{")
        P(body.format(f=fld))
        P("    }")
    P("    apply {")
    for f in used_state: P(f"        {STATEFUL[f][2]}();")
    P("        statefull_features = {")
    P("            " + ", ".join(f"{STATEFUL[f][0]} = {STATEFUL[f][0]}" for f in used_state))
    P("        };")
    P("    }")
    P("}\n")

    # ----- GetStatefullFeaturesDefaultValues -----
    P("control GetStatefullFeaturesDefaultValues(out StatefullFeatures_t statefull_features) {")
    P("    apply {")
    P("        statefull_features = {")
    P("            " + ", ".join(f"{STATEFUL[f][0]} = 0" for f in used_state))
    P("        };")
    P("    }")
    P("}\n")

    P(f"#define INFERENCE_POINT {a.inference_point}")
    P(f"#define MODEL_ID {a.model_id}\n")

    # ----- Features_t -----
    if used_guard:
        P("struct Features_t {")
        for f in used_guard:
            fld, w = GUARDED[f][0], GUARDED[f][1]; P(f"    bit<{w}> {fld};")
        P("}\n")

    # ----- Codewords_t -----
    P("struct Codewords_t {")
    for t in range(ntrees):
        for fi in range(len(feats)):
            P(f"    bit<{widths[fi][t]}> codeword{t}_{fi};")
        if ntrees>1: P("")
    P("}\n")

    multi = ntrees > 1
    if multi:
        P("struct VotingClasses_t {")
        for t in range(ntrees): P(f"    Class_t class{t};")
        P("}\n")

    # ----- InferenceModel -----
    P("control InferenceModel(")
    P("    in Headers_t hdr, in Metadata_t meta, in standard_metadata_t std_meta,")
    P("    in StatefullFeatures_t statefull_features, out Class_t class) {\n")
    P("    Codewords_t codewords = {" + ",".join(["0"]*(ntrees*len(feats))) + "};\n")

    # SetCode actions (one per feature, ntrees args)
    for fi in range(len(feats)):
        args = ", ".join(f"bit<{widths[fi][t]}> code{t}" for t in range(ntrees))
        P(f"    action SetCode{fi}({args}) {{")
        for t in range(ntrees): P(f"        codewords.codeword{t}_{fi} = code{t};")
        P("    }")
    P("    action nop() {}\n")
    if used_guard: P("    Features_t features;")
    P(f"    // FEATURES: {feats}")

    # TableFeature{fi}
    for fi, fname in enumerate(feats):
        P(f"    table TableFeature{fi} {{")
        P(f'        key = {{ {keysrc(fname)}: range @name("feature{fi}"); }}')
        P(f"        actions = {{ @defaultonly nop; SetCode{fi}; }}")
        P(f"        size = 1024;")
        P("        const default_action = nop();")
        P("    }")
    P("")

    if multi:
        P("    VotingClasses_t voting_classes = {" + ",".join(["0"]*ntrees) + "};")
        for t in range(ntrees):
            P(f"    action SetClass{t}(bit<8> classe) {{ voting_classes.class{t} = classe; }}")
    else:
        P("    action SetClass0(bit<8> classe) { class = classe; }")
        P("    action SetClass0ToUnknown() { class = UNKNOWN_CLASS; }")
    P("")

    # CodeTable{t}
    for t in range(ntrees):
        P(f"    table CodeTable{t} {{")
        P("        key = {")
        for fi in range(len(feats)): P(f"            codewords.codeword{t}_{fi}: ternary;")
        P("        }")
        if multi:
            P(f"        actions = {{ @defaultonly nop; SetClass{t}; }}")
            P("        size = 1024;")
            P("        const default_action = nop();")
        else:
            P("        actions = { SetClass0; @defaultonly SetClass0ToUnknown; }")
            P("        size = 1024;")
            P("        const default_action = SetClass0ToUnknown();")
        P("    }")
    P("")

    if multi:
        P("    action SetVotingResult(Class_t vote_result) { class = vote_result; }")
        P("    action SetVotingResultToUnknown() { class = UNKNOWN_CLASS; }")
        P("    table VotingTable {")
        P("        key = {")
        for t in range(ntrees): P(f"            voting_classes.class{t}: exact;")
        P("        }")
        P("        actions = { SetVotingResult; @defaultonly SetVotingResultToUnknown; }")
        P(f"        size = {(n_real+1)**ntrees};")
        P("        const default_action = SetVotingResultToUnknown();")
        P("    }")
    P("")

    # apply
    P("    apply {")
    for f in used_guard:
        fld, w, proto, src = GUARDED[f]
        P(f"        if (hdr.ipv4.protocol == IPv4Proto.{proto}) {{ features.{fld} = {src}; }} else {{ features.{fld} = 0; }}")
    for fi in range(len(feats)): P(f"        TableFeature{fi}.apply();")
    for t in range(ntrees): P(f"        CodeTable{t}.apply();")
    if multi: P("        VotingTable.apply();")
    P(f"        class = class + {a.offset};")
    P(f"        if ({threshold} == class) {{ class = UNKNOWN_CLASS; }}")
    P("    }")
    P("}\n")

    P('#include "dune_ingress_parser.p4"')
    P('#include "dune_verify_checksum.p4"')
    P('#include "dune_ingress.p4"')
    P('#include "dune_egress.p4"')
    P('#include "dune_compute_checksum.p4"')
    P('#include "dune_egress_deparser.p4"\n')
    P("V1Switch(DuneIngressParser(), DuneVerifyChecksum(), DuneIngress(),")
    P("         DuneEgress(), DuneComputeChecksum(), DuneEgressDeparser()) main;")

    open(a.out, "w").write("\n".join(L) + "\n")
    print(f"WROTE {a.out}: {ntrees} trees, {len(feats)} feats, stateful={used_state}, "
          f"guarded={used_guard}, offset={a.offset}, threshold={threshold}, multi={multi}")

if __name__ == "__main__":
    main()
