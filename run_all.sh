#!/bin/bash
# Proves every lemma of the two phase models with the oracle in oracle.py.
# One Tamarin process per lemma; JOBS=2 ./run_all.sh runs two lemmas in parallel.
# Output: results/summary.txt (one line per lemma) and results/<model>_<lemma>.log
cd "$(dirname "$0")"
mkdir -p results
JOBS=${JOBS:-1}; TIMEOUT=${TIMEOUT:-3600}
A="ltk_V ltk_F key_ic key_jc key_ij eph_V eph_F eph_C exec_phaseA authA_V_F authA_V_CS
   authA_F_V authA_F_CS authA_CS_V authA_CS_F secA_vehicle secA_fog secA_cloud
   anonymity no_escrow_V no_escrow_F"
B="ltk_V ltk_F key_ic key_jc key_ij exec_phaseB authB_V_F authB_F_V secB_vehicle secB_fog anonymity"
prove() {   # prove <model> <lemma>
  local f=$1 l=$2 log=results/${1%.spthy}_$2.log s e
  s=$(date +%s.%N)
  timeout $TIMEOUT tamarin-prover --derivcheck-timeout=0 --prove=$l --heuristic=O \
      --oraclename=oracle.py $f 2>&1 \
    | awk '/START INPUT/{skip=1} !skip{print} /END Oracle call/{skip=0}' > $log
  e=$(date +%s.%N)
  printf '%-22s %-14s %s  %.1f s\n' "$f" "$l" \
    "$(grep -E "^  $l \(" $log | sed 's/^ *//; s/^[^ ]* //')" "$(echo "$e - $s" | bc)"
}
export -f prove; export TIMEOUT
: > results/summary.txt
{ for l in $A; do echo IoV_AKA_phaseA.spthy $l; done
  for l in $B; do echo IoV_AKA_phaseB.spthy $l; done; } \
  | xargs -P $JOBS -L 1 bash -c 'prove "$0" "$1"' | tee -a results/summary.txt
