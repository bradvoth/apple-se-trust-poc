#!/bin/bash
# Produce the signer matrix: the same dummy binary signed by each of our
# identities, plus unsigned and ad-hoc controls.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=lib-trust.sh
. "$PWD/lib-trust.sh"
KC="$PWD/work/poc-signing.keychain-db"

# codesign --keychain still needs the keychain in the search list.
poc_keychain_add "$KC"

./build.sh >/dev/null

cp bin/pocclient bin/pocclient-unsigned
cp bin/pocclient bin/pocclient-adhoc    && codesign -s - -i com.poc.client -f bin/pocclient-adhoc
cp bin/pocclient bin/pocclient-signedA  && codesign --keychain "$KC" -s "POC Software Signing A"     -i com.poc.client -f bin/pocclient-signedA
cp bin/pocclient bin/pocclient-signedB  && codesign --keychain "$KC" -s "POC Software Signing B"     -i com.poc.client -f bin/pocclient-signedB
cp bin/pocclient bin/pocclient-signedC  && codesign --keychain "$KC" -s "Rogue Software Signing C"   -i com.poc.client -f bin/pocclient-signedC
# Same identity, but with the hardened runtime: library validation on, DYLD_* ignored.
cp bin/pocclient bin/pocclient-hardA    && codesign --keychain "$KC" --options runtime -s "POC Software Signing A" -i com.poc.client -f bin/pocclient-hardA

# "Attacker" library for run-injection.sh: unsigned, from no CA.
clang -fobjc-arc -O1 -dynamiclib -Wno-deprecated-declarations \
  -framework Foundation -framework Security -o bin/libinject.dylib tools/libinject.m

printf '%-22s  %-18s  %s\n' BINARY SIGNED-BY "DESIGNATED REQUIREMENT"
for b in unsigned adhoc signedA signedB signedC hardA; do
  case $b in
    unsigned) who="(nothing)";;
    adhoc)    who="ad-hoc";;
    signedA)  who="Signing A";;
    hardA)    who="Signing A (runtime)";;
    signedB)  who="Signing B";;
    signedC)  who="Signing C";;
  esac
  dr=$(codesign -d -r- "bin/pocclient-$b" 2>/dev/null | sed -n 's/^designated => //p')
  printf '%-22s  %-18s  %s\n' "pocclient-$b" "$who" "${dr:-（none)}"
done
