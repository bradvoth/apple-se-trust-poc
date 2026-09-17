#!/bin/bash
# Trust the tiered PKI and set up a keychain holding the team signing leaves.
#
# Uses the same user-domain, no-sudo approach as setup-trust.sh. The difference is
# that a three-deep chain needs the INTERMEDIATE certificates findable by trustd as
# well as the root, or codesign cannot build the chain ("MissingIntermediate").
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
# shellcheck source=lib-trust.sh
. "$ROOT/lib-trust.sh"
POC_ROOT="$ROOT"
LOGIN="$HOME/Library/Keychains/login.keychain-db"
SIGNKC="$ROOT/work/poc-signing-tiered.keychain-db"
KCPW=poc

[ -f pki/ent/ent-root.crt ] || { echo "run ./make-pki-tiered.sh first"; exit 1; }

echo "== put the whole chain in the login keychain =="
# The root AND both intermediates: trustd builds the chain from keychains in its
# search path, and a missing intermediate is the failure we hit earlier.
for c in pki/ent/ent-root.crt pki/ent/teamA.crt pki/ent/teamB.crt; do
  security add-certificates -k "$LOGIN" "$c" 2>/dev/null || true
  echo "  added $(basename "$c")"
done

echo "== trust the enterprise root for code signing =="
trust_root() {
  local ca="$1" name i
  name=$(openssl x509 -in "$ca" -noout -subject | sed -n 's/^subject=.*CN *= *\([^,]*\).*/\1/p')
  if poc_trust_list | grep -Fxq "$name"; then
    echo "  $name: already trusted, skipping (avoids the auth prompt)"
    return 0
  fi
  for i in 1 2; do
    if poc_trust_add "$ca" 2>/tmp/trerr.txt; then
      echo "  $name: trusted"
      return 0
    fi
    [ "$i" = 1 ] && { echo "  $name: retrying after a pause"; sleep 3; }
  done
  echo "  $name: FAILED to trust:" >&2
  sed 's/^/    /' /tmp/trerr.txt >&2
  return 1
}
# Same fast path as setup-trust.sh: only touch trust settings when the chain does not
# already verify, because adding a trust setting is the only step that can prompt.
sleep 1
if security verify-cert -p codeSign -c pki/leaves3/teamA1.crt >/dev/null 2>&1; then
  echo "  chain already verifies; no trust settings touched"
else
  trust_root pki/ent/ent-root.crt
fi
security dump-trust-settings 2>&1 | sed 's/^/  /' || true
if ! security verify-cert -p codeSign -c pki/leaves3/teamA1.crt >/dev/null 2>&1; then
  echo "  teamA1 still does not verify after trusting the enterprise root" >&2
  exit 1
fi
echo "  teamA1 chains to a trusted root: ok"

echo "== signing keychain =="
security delete-keychain "$SIGNKC" 2>/dev/null || true
security create-keychain -p "$KCPW" "$SIGNKC"
security set-keychain-settings -lut 21600 "$SIGNKC"
security unlock-keychain -p "$KCPW" "$SIGNKC"
for n in teamA1 teamA2 teamB1; do
  security import "work/p12-3/$n.p12" -k "$SIGNKC" -P "$KCPW" -A -f pkcs12
done
for c in pki/ent/ent-root.crt pki/ent/teamA.crt pki/ent/teamB.crt; do
  security add-certificates -k "$SIGNKC" "$c" 2>/dev/null || true
done
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KCPW" "$SIGNKC" >/dev/null

echo "== search list =="
# Additive, so both PKI flows can coexist in either run order. `codesign --keychain`
# alone is not enough: a keychain missing from the search list makes codesign report
# "no identity found" even when it is passed explicitly.
poc_keychain_ensure_login
poc_keychain_add "$SIGNKC"
poc_keychain_list | sed 's/^/  /'

echo "== identities =="
security find-identity -p codesigning "$SIGNKC"

echo "== verification =="
for l in teamA1 teamA2 teamB1; do
  if security verify-cert -p codeSign -c "pki/leaves3/$l.crt" >/dev/null 2>&1; then
    echo "  $l chains to a trusted root: ok"
  else
    echo "  $l does NOT verify; stale trust settings for a regenerated root?" >&2
    exit 1
  fi
done
