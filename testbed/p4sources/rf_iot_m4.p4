#include <core.p4>
#include <v1model.p4>
#include "dune_headers.p4"

struct StatefullFeatures_t {
    bit<16> total_length;
    bit<8> syn_flag_count;
}

control UpdateAndGetStatefullFeatures(
    in Headers_t hdr, in standard_metadata_t std_meta, in Hash_t hashes,
    in PktCount_t pkt_count, in bool new_flow, out StatefullFeatures_t statefull_features) {
    bit<16> total_length;
    register<bit<16>>(NB_REG_ENTRIES) flows_total_length;
    action GetUpdateTotalLength () {
        if (new_flow) { total_length = 0; } else { flows_total_length.read(total_length, hashes.reg_idx32); }
        total_length += hdr.ipv4.total_length;
        flows_total_length.write(hashes.reg_idx32, total_length);
    }
    bit<8> syn_flag_count;
    register<bit<8>>(NB_REG_ENTRIES) flows_syn_flag_count;
    action GetUpdateSYNFlagCount () {
        flows_syn_flag_count.read(syn_flag_count, hashes.reg_idx32);
        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.syn == 1) { syn_flag_count = syn_flag_count + 1; flows_syn_flag_count.write(hashes.reg_idx32, syn_flag_count); }
    }
    apply {
        GetUpdateTotalLength();
        GetUpdateSYNFlagCount();
        statefull_features = {
            total_length = total_length, syn_flag_count = syn_flag_count
        };
    }
}

control GetStatefullFeaturesDefaultValues(out StatefullFeatures_t statefull_features) {
    apply {
        statefull_features = {
            total_length = 0, syn_flag_count = 0
        };
    }
}

#define INFERENCE_POINT 4
#define MODEL_ID 4

struct Features_t {
    bit<16> udp_len;
    bit<1> tcp_syn;
    bit<1> tcp_rst;
    bit<16> tcp_window;
}

struct Codewords_t {
    bit<3> codeword0_0;
    bit<22> codeword0_1;
    bit<4> codeword0_2;
    bit<4> codeword0_3;
    bit<2> codeword0_4;
    bit<1> codeword0_5;
    bit<1> codeword0_6;
    bit<1> codeword0_7;
    bit<4> codeword0_8;
}

control InferenceModel(
    in Headers_t hdr, in Metadata_t meta, in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features, out Class_t class) {

    Codewords_t codewords = {0,0,0,0,0,0,0,0,0};

    action SetCode0(bit<3> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<22> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<4> code0) {
        codewords.codeword0_2 = code0;
    }
    action SetCode3(bit<4> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<2> code0) {
        codewords.codeword0_4 = code0;
    }
    action SetCode5(bit<1> code0) {
        codewords.codeword0_5 = code0;
    }
    action SetCode6(bit<1> code0) {
        codewords.codeword0_6 = code0;
    }
    action SetCode7(bit<1> code0) {
        codewords.codeword0_7 = code0;
    }
    action SetCode8(bit<4> code0) {
        codewords.codeword0_8 = code0;
    }
    action nop() {}

    Features_t features;
    // FEATURES: ['dstport', 'srcport', 'udp.length', 'ip.len', 'tcp.flags.syn', 'Packet Length Total', 'tcp.flags.reset', 'SYN Flag Count', 'tcp.window_size_value']
    table TableFeature0 {
        key = { meta.dst_port: range @name("feature0"); }
        actions = { @defaultonly nop; SetCode0; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature1 {
        key = { meta.src_port: range @name("feature1"); }
        actions = { @defaultonly nop; SetCode1; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature2 {
        key = { features.udp_len: range @name("feature2"); }
        actions = { @defaultonly nop; SetCode2; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature3 {
        key = { hdr.ipv4.total_length: range @name("feature3"); }
        actions = { @defaultonly nop; SetCode3; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature4 {
        key = { features.tcp_syn: range @name("feature4"); }
        actions = { @defaultonly nop; SetCode4; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature5 {
        key = { statefull_features.total_length: range @name("feature5"); }
        actions = { @defaultonly nop; SetCode5; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature6 {
        key = { features.tcp_rst: range @name("feature6"); }
        actions = { @defaultonly nop; SetCode6; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature7 {
        key = { statefull_features.syn_flag_count: range @name("feature7"); }
        actions = { @defaultonly nop; SetCode7; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature8 {
        key = { features.tcp_window: range @name("feature8"); }
        actions = { @defaultonly nop; SetCode8; }
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
            codewords.codeword0_8: ternary;
        }
        actions = { SetClass0; @defaultonly SetClass0ToUnknown; }
        size = 1024;
        const default_action = SetClass0ToUnknown();
    }


    apply {
        if (hdr.ipv4.protocol == IPv4Proto.UDP) { features.udp_len = hdr.udp.length; } else { features.udp_len = 0; }
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_syn = hdr.tcp.syn; } else { features.tcp_syn = 0; }
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_rst = hdr.tcp.rst; } else { features.tcp_rst = 0; }
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_window = hdr.tcp.window; } else { features.tcp_window = 0; }
        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();
        TableFeature3.apply();
        TableFeature4.apply();
        TableFeature5.apply();
        TableFeature6.apply();
        TableFeature7.apply();
        TableFeature8.apply();
        CodeTable0.apply();
        class = class + 6;
        if (8 == class) { class = UNKNOWN_CLASS; }
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
