#!/bin/bash
# Does code injected into a permitted binary inherit its keychain access?
# Compares a plain signed build against one signed with the hardened runtime.
set -uo pipefail
cd "$(dirname "$0")"
KC="$PWD/work/poc-test.keychain-db"
export POC_KC="$KC" POC_LABEL=pin-root-ca1

run() { # $1=label  $2=binary
  local out
  out=$(DYLD_INSERT_LIBRARIES="$PWD/bin/libinject.dylib" "$2" "$KC" "pin-root-ca1" 2>&1)
  local inj="not loaded (injection blocked)"
  case "$out" in
    "[inject]"*|*"
[inject]"*) inj=$(printf '%s' "$out" | grep -E 'GOT THE KEY|DENIED|NO KEY' | head -1);;
  esac
  printf '%-34s %-22s %s\n' "$1" "$inj" "$(printf '%s' "$out" | grep -E '^RESULT' | head -1)"
}

printf '%-34s %-22s %s\n' BINARY INJECTED-CODE "PROCESS RESULT"
run "pocclient-signedA (no runtime)"      ./bin/pocclient-signedA
run "pocclient-hardA (hardened runtime)" ./bin/pocclient-hardA
echo
echo "The hardened binary keeps its own access but refuses to load the foreign dylib,"
echo "because the hardened runtime makes dyld ignore DYLD_INSERT_LIBRARIES and turns"
echo "on library validation."
