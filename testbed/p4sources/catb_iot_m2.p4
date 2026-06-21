#include <core.p4>
#include <v1model.p4>
#include "dune_headers.p4"

struct StatefullFeatures_t {
    bit<8> syn_flag_count;
    bit<16> total_length;
}

control UpdateAndGetStatefullFeatures(
    in Headers_t hdr, in standard_metadata_t std_meta, in Hash_t hashes,
    in PktCount_t pkt_count, in bool new_flow, out StatefullFeatures_t statefull_features) {
    bit<8> syn_flag_count;
    register<bit<8>>(NB_REG_ENTRIES) flows_syn_flag_count;
    action GetUpdateSYNFlagCount () {
        flows_syn_flag_count.read(syn_flag_count, hashes.reg_idx32);
        if (hdr.ipv4.protocol == IPv4Proto.TCP && hdr.tcp.syn == 1) { syn_flag_count = syn_flag_count + 1; flows_syn_flag_count.write(hashes.reg_idx32, syn_flag_count); }
    }
    bit<16> total_length;
    register<bit<16>>(NB_REG_ENTRIES) flows_total_length;
    action GetUpdateTotalLength () {
        if (new_flow) { total_length = 0; } else { flows_total_length.read(total_length, hashes.reg_idx32); }
        total_length += hdr.ipv4.total_length;
        flows_total_length.write(hashes.reg_idx32, total_length);
    }
    apply {
        GetUpdateSYNFlagCount();
        GetUpdateTotalLength();
        statefull_features = {
            syn_flag_count = syn_flag_count, total_length = total_length
        };
    }
}

control GetStatefullFeaturesDefaultValues(out StatefullFeatures_t statefull_features) {
    apply {
        statefull_features = {
            syn_flag_count = 0, total_length = 0
        };
    }
}

#define INFERENCE_POINT 4
#define MODEL_ID 2

struct Features_t {
    bit<4> tcp_len;
}

struct Codewords_t {
    bit<34> codeword0_0;
    bit<14> codeword0_1;
    bit<7> codeword0_2;
    bit<5> codeword0_3;
    bit<7> codeword0_4;
    bit<13> codeword0_5;
    bit<4> codeword0_6;

    bit<28> codeword1_0;
    bit<15> codeword1_1;
    bit<8> codeword1_2;
    bit<5> codeword1_3;
    bit<12> codeword1_4;
    bit<13> codeword1_5;
    bit<3> codeword1_6;

    bit<34> codeword2_0;
    bit<10> codeword2_1;
    bit<7> codeword2_2;
    bit<4> codeword2_3;
    bit<11> codeword2_4;
    bit<13> codeword2_5;
    bit<5> codeword2_6;

}

struct VotingClasses_t {
    Class_t class0;
    Class_t class1;
    Class_t class2;
}

control InferenceModel(
    in Headers_t hdr, in Metadata_t meta, in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features, out Class_t class) {

    Codewords_t codewords = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    action SetCode0(bit<34> code0, bit<28> code1, bit<34> code2) {
        codewords.codeword0_0 = code0;
        codewords.codeword1_0 = code1;
        codewords.codeword2_0 = code2;
    }
    action SetCode1(bit<14> code0, bit<15> code1, bit<10> code2) {
        codewords.codeword0_1 = code0;
        codewords.codeword1_1 = code1;
        codewords.codeword2_1 = code2;
    }
    action SetCode2(bit<7> code0, bit<8> code1, bit<7> code2) {
        codewords.codeword0_2 = code0;
        codewords.codeword1_2 = code1;
        codewords.codeword2_2 = code2;
    }
    action SetCode3(bit<5> code0, bit<5> code1, bit<4> code2) {
        codewords.codeword0_3 = code0;
        codewords.codeword1_3 = code1;
        codewords.codeword2_3 = code2;
    }
    action SetCode4(bit<7> code0, bit<12> code1, bit<11> code2) {
        codewords.codeword0_4 = code0;
        codewords.codeword1_4 = code1;
        codewords.codeword2_4 = code2;
    }
    action SetCode5(bit<13> code0, bit<13> code1, bit<13> code2) {
        codewords.codeword0_5 = code0;
        codewords.codeword1_5 = code1;
        codewords.codeword2_5 = code2;
    }
    action SetCode6(bit<4> code0, bit<3> code1, bit<5> code2) {
        codewords.codeword0_6 = code0;
        codewords.codeword1_6 = code1;
        codewords.codeword2_6 = code2;
    }
    action nop() {}

    Features_t features;
    // FEATURES: ['srcport', 'dstport', 'ip.ttl', 'SYN Flag Count', 'Packet Length Total', 'ip.len', 'tcp.hdr_len']
    table TableFeature0 {
        key = { meta.src_port: range @name("feature0"); }
        actions = { @defaultonly nop; SetCode0; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature1 {
        key = { meta.dst_port: range @name("feature1"); }
        actions = { @defaultonly nop; SetCode1; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature2 {
        key = { hdr.ipv4.ttl: range @name("feature2"); }
        actions = { @defaultonly nop; SetCode2; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature3 {
        key = { statefull_features.syn_flag_count: range @name("feature3"); }
        actions = { @defaultonly nop; SetCode3; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature4 {
        key = { statefull_features.total_length: range @name("feature4"); }
        actions = { @defaultonly nop; SetCode4; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature5 {
        key = { hdr.ipv4.total_length: range @name("feature5"); }
        actions = { @defaultonly nop; SetCode5; }
        size = 1024;
        const default_action = nop();
    }
    table TableFeature6 {
        key = { features.tcp_len: range @name("feature6"); }
        actions = { @defaultonly nop; SetCode6; }
        size = 1024;
        const default_action = nop();
    }

    VotingClasses_t voting_classes = {0,0,0};
    action SetClass0(bit<8> classe) { voting_classes.class0 = classe; }
    action SetClass1(bit<8> classe) { voting_classes.class1 = classe; }
    action SetClass2(bit<8> classe) { voting_classes.class2 = classe; }

    table CodeTable0 {
        key = {
            codewords.codeword0_0: ternary;
            codewords.codeword0_1: ternary;
            codewords.codeword0_2: ternary;
            codewords.codeword0_3: ternary;
            codewords.codeword0_4: ternary;
            codewords.codeword0_5: ternary;
            codewords.codeword0_6: ternary;
        }
        actions = { @defaultonly nop; SetClass0; }
        size = 1024;
        const default_action = nop();
    }
    table CodeTable1 {
        key = {
            codewords.codeword1_0: ternary;
            codewords.codeword1_1: ternary;
            codewords.codeword1_2: ternary;
            codewords.codeword1_3: ternary;
            codewords.codeword1_4: ternary;
            codewords.codeword1_5: ternary;
            codewords.codeword1_6: ternary;
        }
        actions = { @defaultonly nop; SetClass1; }
        size = 1024;
        const default_action = nop();
    }
    table CodeTable2 {
        key = {
            codewords.codeword2_0: ternary;
            codewords.codeword2_1: ternary;
            codewords.codeword2_2: ternary;
            codewords.codeword2_3: ternary;
            codewords.codeword2_4: ternary;
            codewords.codeword2_5: ternary;
            codewords.codeword2_6: ternary;
        }
        actions = { @defaultonly nop; SetClass2; }
        size = 1024;
        const default_action = nop();
    }

    action SetVotingResult(Class_t vote_result) { class = vote_result; }
    action SetVotingResultToUnknown() { class = UNKNOWN_CLASS; }
    table VotingTable {
        key = {
            voting_classes.class0: exact;
            voting_classes.class1: exact;
            voting_classes.class2: exact;
        }
        actions = { SetVotingResult; @defaultonly SetVotingResultToUnknown; }
        size = 125;
        const default_action = SetVotingResultToUnknown();
    }

    apply {
        if (hdr.ipv4.protocol == IPv4Proto.TCP) { features.tcp_len = hdr.tcp.data_offset; } else { features.tcp_len = 0; }
        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();
        TableFeature3.apply();
        TableFeature4.apply();
        TableFeature5.apply();
        TableFeature6.apply();
        CodeTable0.apply();
        CodeTable1.apply();
        CodeTable2.apply();
        VotingTable.apply();
        class = class + 1;
        if (6 == class) { class = UNKNOWN_CLASS; }
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
