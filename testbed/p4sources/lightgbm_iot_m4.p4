#include <core.p4>
#include <v1model.p4>
#include "dune_headers.p4"

struct StatefullFeatures_t {
    bit<16> max_length;
}

control UpdateAndGetStatefullFeatures(
    in Headers_t hdr, in standard_metadata_t std_meta, in Hash_t hashes,
    in PktCount_t pkt_count, in bool new_flow, out StatefullFeatures_t statefull_features) {
    bit<16> max_length;
    register<bit<16>>(NB_REG_ENTRIES) flows_max_length;
    action GetUpdateMaxLength () {
        flows_max_length.read(max_length, hashes.reg_idx32);
        if (new_flow || max_length < hdr.ipv4.total_length) { max_length = hdr.ipv4.total_length; flows_max_length.write(hashes.reg_idx32, max_length); }
    }
    apply {
        GetUpdateMaxLength();
        statefull_features = {
            max_length = max_length
        };
    }
}

control GetStatefullFeaturesDefaultValues(out StatefullFeatures_t statefull_features) {
    apply {
        statefull_features = {
            max_length = 0
        };
    }
}

#define INFERENCE_POINT 4
#define MODEL_ID 4

struct Features_t {
    bit<16> tcp_window;
    bit<1> tcp_fin;
}

struct Codewords_t {
    bit<4> codeword0_0;
    bit<33> codeword0_1;
    bit<12> codeword0_2;
    bit<15> codeword0_3;
    bit<2> codeword0_4;
    bit<18> codeword0_5;
}

control InferenceModel(
    in Headers_t hdr, in Metadata_t meta, in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features, out Class_t class) {

    Codewords_t codewords = {0,0,0,0,0,0};

    action SetCode0(bit<4> code0) {
        codewords.codeword0_0 = code0;
    }
    action SetCode1(bit<33> code0) {
        codewords.codeword0_1 = code0;
    }
    action SetCode2(bit<12> code0) {
        codewords.codeword0_2 = code0;
    }
    action SetCode3(bit<15> code0) {
        codewords.codeword0_3 = code0;
    }
    action SetCode4(bit<2> code0) {
        codewords.codeword0_4 = code0;
    }
    action SetCode5(bit<18> code0) {
        codewords.codeword0_5 = code0;
    }
    action nop() {}

    Features_t features;
    // FEATURES: ['dstport', 'srcport', 'ip.len', 'tcp.window_size_value', 'tcp.flags.fin', 'Max Packet Length']
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
        key = { hdr.ipv4.total_length: range @name("feature2"); }
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
        key = { features.tcp_fin: range @name("feature4"); }
        actions = { @defaultonly nop; SetCode4; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature5 {
        key = { statefull_features.max_length: range @name("feature5"); }
        actions = { @defaultonly nop; SetCode5; }
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
        }
        actions = { SetClass0; @defaultonly SetClass0ToUnknown; }
        size = 1024;
        const default_action = SetClass0ToUnknown();
    }


    apply {
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_window = hdr.tcp.window; } else { features.tcp_window = 0; }
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_fin = hdr.tcp.fin; } else { features.tcp_fin = 0; }
        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();
        TableFeature3.apply();
        TableFeature4.apply();
        TableFeature5.apply();
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
