#include <core.p4>
#include <v1model.p4>
#include "dune_headers.p4"

struct StatefullFeatures_t {
    bit<16> total_length;
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
    apply {
        GetUpdateTotalLength();
        statefull_features = {
            total_length = total_length
        };
    }
}

control GetStatefullFeaturesDefaultValues(out StatefullFeatures_t statefull_features) {
    apply {
        statefull_features = {
            total_length = 0
        };
    }
}

#define INFERENCE_POINT 4
#define MODEL_ID 1

struct Codewords_t {
    bit<11> codeword0_0;
    bit<15> codeword0_1;
    bit<4> codeword0_2;
    bit<10> codeword0_3;

    bit<5> codeword1_0;
    bit<21> codeword1_1;
    bit<3> codeword1_2;
    bit<11> codeword1_3;

    bit<9> codeword2_0;
    bit<13> codeword2_1;
    bit<4> codeword2_2;
    bit<14> codeword2_3;

}

struct VotingClasses_t {
    Class_t class0;
    Class_t class1;
    Class_t class2;
}

control InferenceModel(
    in Headers_t hdr, in Metadata_t meta, in standard_metadata_t std_meta,
    in StatefullFeatures_t statefull_features, out Class_t class) {

    Codewords_t codewords = {0,0,0,0,0,0,0,0,0,0,0,0};

    action SetCode0(bit<11> code0, bit<5> code1, bit<9> code2) {
        codewords.codeword0_0 = code0;
        codewords.codeword1_0 = code1;
        codewords.codeword2_0 = code2;
    }
    action SetCode1(bit<15> code0, bit<21> code1, bit<13> code2) {
        codewords.codeword0_1 = code0;
        codewords.codeword1_1 = code1;
        codewords.codeword2_1 = code2;
    }
    action SetCode2(bit<4> code0, bit<3> code1, bit<4> code2) {
        codewords.codeword0_2 = code0;
        codewords.codeword1_2 = code1;
        codewords.codeword2_2 = code2;
    }
    action SetCode3(bit<10> code0, bit<11> code1, bit<14> code2) {
        codewords.codeword0_3 = code0;
        codewords.codeword1_3 = code1;
        codewords.codeword2_3 = code2;
    }
    action nop() {}

    // FEATURES: ['dstport', 'srcport', 'ip.ttl', 'ip.len']
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
        key = { hdr.ipv4.ttl: range @name("feature2"); }
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
        TableFeature0.apply();
        TableFeature1.apply();
        TableFeature2.apply();
        TableFeature3.apply();
        CodeTable0.apply();
        CodeTable1.apply();
        CodeTable2.apply();
        VotingTable.apply();
        class = class + 0;
        if (5 == class) { class = UNKNOWN_CLASS; }
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
