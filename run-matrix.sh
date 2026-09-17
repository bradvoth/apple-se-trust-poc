#!/bin/bash
# Run every signed/unsigned caller against every ACL-restricted key and print
# the resulting access decision. Key requirements are printed by make-keys.sh.
set -uo pipefail
cd "$(dirname "$0")"
TESTKC="$PWD/work/poc-test.keychain-db"

KEYS=(pin-root-ca1 pin-leaf-a pin-leaf-b anchor-trusted identifier-only deny-all)
BINS=(unsigned adhoc signedA signedB signedC)

echo "=================== MATRIX ==================="
printf '%-9s' "caller"
for k in "${KEYS[@]}"; do printf '%-17s' "$k"; done
echo

for b in "${BINS[@]}"; do
  printf '%-9s' "$b"
  for k in "${KEYS[@]}"; do
    out=$(./bin/pocclient-$b "$TESTKC" "$k" 2>&1)
    case "$out" in
      *GRANTED*)       r="GRANTED";;
      *DENIED_USE*)    u=$(echo "$out" | sed -n 's/.*SecKeyCreateSignature *-> *\([-0-9]*\).*/\1/p'); r="deny-use $u";;
      *DENIED_LOOKUP*) r="deny-lookup";;
      *)               r="?? ${out:0:24}";;
    esac
    printf '%-17s' "$r"
  done
  echo
done
