#include <core.p4>
#include <v1model.p4>
#include "dune_headers.p4"

struct StatefullFeatures_t {
    bit<8> psh_flag_count;
}

control UpdateAndGetStatefullFeatures(
    in Headers_t hdr, in standard_metadata_t std_meta, in Hash_t hashes,
    in PktCount_t pkt_count, in bool new_flow, out StatefullFeatures_t statefull_features) {
    bit<8> psh_flag_count;
    register<bit<8>>(NB_REG_ENTRIES) flows_psh_flag_count;
    action GetUpdatePSHFlagCount () {
        flows_psh_flag_count.read(psh_flag_count, hashes.reg_idx32);
        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.psh == 1) { psh_flag_count = psh_flag_count + 1; flows_psh_flag_count.write(hashes.reg_idx32, psh_flag_count); }
    }
    apply {
        GetUpdatePSHFlagCount();
        statefull_features = {
            psh_flag_count = psh_flag_count
        };
    }
}

control GetStatefullFeaturesDefaultValues(out StatefullFeatures_t statefull_features) {
    apply {
        statefull_features = {
            psh_flag_count = 0
        };
    }
}

#define INFERENCE_POINT 4
#define MODEL_ID 3

struct Features_t {
    bit<1> tcp_fin;
    bit<16> tcp_window;
    bit<4> tcp_len;
    bit<16> udp_len;
}

struct Codewords_t {
    bit<7> codeword0_0;
    bit<2> codeword0_1;
    bit<34> codeword0_2;
    bit<14> codeword0_3;
    bit<13> codeword0_4;
    bit<3> codeword0_5;
    bit<2> codeword0_6;
    bit<9> codeword0_7;
}

control InferenceModel(
    in Headers_t hdr, in Metadata_t meta, in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features, out Class_t class) {

    Codewords_t codewords = {0,0,0,0,0,0,0,0};

    action SetCode0(bit<7> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<2> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<34> code0) {
        codewords.codeword0_2 = code0;
    }
    action SetCode3(bit<14> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<13> code0) {
        codewords.codeword0_4 = code0;
    }
    action SetCode5(bit<3> code0) {
        codewords.codeword0_5 = code0;
    }
    action SetCode6(bit<2> code0) {
        codewords.codeword0_6 = code0;
    }
    action SetCode7(bit<9> code0) {
        codewords.codeword0_7 = code0;
    }
    action nop() {}

    Features_t features;
    // FEATURES: ['dstport', 'tcp.flags.fin', 'srcport', 'tcp.window_size_value', 'ip.len', 'tcp.hdr_len', 'udp.length', 'PSH Flag Count']
    table TableFeature0 {
        key = { meta.dst_port: range @name("feature0"); }
        actions = { @defaultonly nop; SetCode0; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature1 {
        key = { features.tcp_fin: range @name("feature1"); }
        actions = { @defaultonly nop; SetCode1; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature2 {
        key = { meta.src_port: range @name("feature2"); }
        actions = { @defaultonly nop; SetCode2; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature3 {
        key = { features.tcp_window: range @name("feature3"); }
        actions = { @defaultonly nop; SetCode3; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature4 {
        key = { hdr.ipv4.total_length: range @name("feature4"); }
        actions = { @defaultonly nop; SetCode4; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature5 {
        key = { features.tcp_len: range @name("feature5"); }
        actions = { @defaultonly nop; SetCode5; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature6 {
        key = { features.udp_len: range @name("feature6"); }
        actions = { @defaultonly nop; SetCode6; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature7 {
        key = { statefull_features.psh_flag_count: range @name("feature7"); }
        actions = { @defaultonly nop; SetCode7; }
        size = 1024;
        const default_action = nop();
    }

    action SetClass0(bit<8> classe) { class = classe; }
    action SetClass0ToUnknown() { class = UNKNOWN_CLASS; }

    table CodeTable0 {
        key = {
            codewords.codeword0_0: ternary;
            codewords.codeword0_1: ternary;
            codewords.codeword0_2: ternary;
            codewords.codeword0_3: ternary;
            codewords.codeword0_4: ternary;
            codewords.codeword0_5: ternary;
            codewords.codeword0_6: ternary;
            codewords.codeword0_7: ternary;
        }
        actions = { SetClass0; @defaultonly SetClass0ToUnknown; }
        size = 1024;
        const default_action = SetClass0ToUnknown();
    }


    apply {
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_fin = hdr.tcp.fin; } else { features.tcp_fin = 0; }
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_window = hdr.tcp.window; } else { features.tcp_window = 0; }
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_len = hdr.tcp.data_offset; } else { features.tcp_len = 0; }
        if (hdr.ipv4.protocol == IPv4Proto.UDP) { features.udp_len = hdr.udp.length; } else { features.udp_len = 0; }
        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();
        TableFeature3.apply();
        TableFeature4.apply();
        TableFeature5.apply();
        TableFeature6.apply();
        TableFeature7.apply();
        CodeTable0.apply();
        class = class + 5;
        if (7 == class) { class = UNKNOWN_CLASS; }
    }
}

#include "dune_ingress_parser.p4"
#include "dune_verify_checksum.p4"
#include "dune_ingress.p4"
#include "dune_egress.p4"
#include "dune_compute_checksum.p4"
#include "dune_egress_deparser.p4"

V1Switch(DuneIngressParser(), DuneVerifyChecksum(), DuneIngress(),
         DuneEgress(), DuneComputeChecksum(), DuneEgressDeparser()) main;
