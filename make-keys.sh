#!/bin/bash
# Build the ACL-restricted test keys. Each key is pinned to a different code
# requirement so we can compare the access decisions side by side.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
TESTKC="$ROOT/work/poc-test.keychain-db"

CA1=$(openssl x509 -in pki/ca1/ca.crt   -outform DER | shasum -a 1 | cut -d' ' -f1)
LEAF_A=$(openssl x509 -in pki/leaves/signerA.crt -outform DER | shasum -a 1 | cut -d' ' -f1)
LEAF_B=$(openssl x509 -in pki/leaves/signerB.crt -outform DER | shasum -a 1 | cut -d' ' -f1)

security delete-keychain "$TESTKC" 2>/dev/null || true
security create-keychain -p poc "$TESTKC"
security set-keychain-settings -lut 21600 "$TESTKC"
security unlock-keychain -p poc "$TESTKC"

echo "CA1=$CA1"
echo "leafA=$LEAF_A"
echo

S='identifier "com.poc.client"'
./bin/pocsetup mkkeyreq "$TESTKC" pin-root-ca1   "$S and certificate root = H\"$CA1\""
echo
./bin/pocsetup mkkeyreq "$TESTKC" pin-leaf-a     "$S and certificate leaf = H\"$LEAF_A\""
echo
./bin/pocsetup mkkeyreq "$TESTKC" pin-leaf-b     "$S and certificate leaf = H\"$LEAF_B\""
echo
./bin/pocsetup mkkeyreq "$TESTKC" anchor-trusted "$S and anchor trusted"
echo
./bin/pocsetup mkkeyreq "$TESTKC" identifier-only "$S"
echo
./bin/pocsetup mkkeyreq "$TESTKC" deny-all       "$S and certificate leaf = H\"0000000000000000000000000000000000000000\""

# Record what each CA/leaf hash means, for the report.
cat > work/pins.txt <<EOF
CA1   (POC Private Root CA 1)   $CA1
CA2   (POC Rogue Root CA 2)     $(openssl x509 -in pki/ca2/ca.crt -outform DER | shasum -a 1 | cut -d' ' -f1)
leafA (POC Software Signing A)  $LEAF_A
leafB (POC Software Signing B)  $LEAF_B
leafC (Rogue Software Signing C) $(openssl x509 -in pki/leaves/signerC.crt -outform DER | shasum -a 1 | cut -d' ' -f1)
EOF
echo
echo "=== keys in $TESTKC ==="
# `grep` finding nothing would exit non-zero and, under `set -e`, fail the script;
# and dump-keychain does not label these items. find-key lists them properly.
security find-key "$TESTKC" 2>/dev/null | sed -n 's/^    0x00000001 <blob>="\(.*\)"$/  \1/p' | sort -u || true
echo "done"
