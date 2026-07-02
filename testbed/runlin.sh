#!/bin/bash
# One line-topology run: testbed/runlin.sh <model> <pps> [logfile]
# Lab-only helper (needs mininet/BMv2 + ~/src/p4setup.bash, same as the Makefile).
set -u
m=${1:?model}; pps=${2:?pps}; log=${3:-$HOME/lin_${m}${pps}.log}
sudo mn -c >/dev/null 2>&1
source ~/src/p4setup.bash
cd "$(dirname "$0")"
exec make run-linear-test MODELS=configs/models/${m}_ton.json \
  TEST_PCAP=../data/output/ToN_IoT_test.pcap \
  GROUND_TRUTH_FILE=../data/output/ToN_IoT_Flow_PktCounts.csv \
  TEST_PPS=${pps} PODS=1 SPINES=1 LEAFS=1 SUPER_SPINES=1 HOSTS_PER_LEAF=1 \
  SAVE_RESULTS=NO > "$log" 2>&1
