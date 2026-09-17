#!/bin/bash
# Trust the POC CAs and set up the keychain that holds the signing identities.
#
# Everything here is done in the USER domain, so no sudo and no Apple Developer
# account are required. It does modify your login keychain and your user trust
# settings; ./teardown.sh undoes all of it.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
# shellcheck source=lib-trust.sh
. "$ROOT/lib-trust.sh"
POC_ROOT="$ROOT"
LOGIN="$HOME/Library/Keychains/login.keychain-db"
SIGNKC="$ROOT/work/poc-signing.keychain-db"
KCPW=poc

[ -f pki/ca1/ca.crt ] || { echo "run ./make-pki.sh first"; exit 1; }

echo "== CAs must be findable by trustd =="
# The root has to be in a keychain that trustd searches. The login keychain works;
# a bespoke side keychain does not, even when it is in the search list.
security add-certificates -k "$LOGIN" pki/ca1/ca.crt pki/ca2/ca.crt 2>/dev/null || true

# A chain that already verifies needs no trust work at all. Check that FIRST: adding a
# trust setting is the only step here that can raise an authentication prompt, so we
# want to reach it as rarely as possible.
verify_trust() { security verify-cert -p codeSign -c pki/leaves/signerA.crt >/dev/null 2>&1; }

echo "== trust both CAs for code signing (user domain) =="
# Idempotent, and deliberately so: re-adding a trust setting for a certificate that
# is already trusted raises a "changes to your Certificate Trust Settings"
# authentication prompt. Adding a trust setting for the first time does not.
# Read the trusted names at the point of use, not once up front: poc_trust_drop can
# change the list, and a cached copy would then wrongly report "already trusted".
trust_ca() {
  local ca="$1" name i
  name=$(openssl x509 -in "$ca" -noout -subject | sed -n 's/^subject=.*CN *= *\([^,]*\).*/\1/p')
  if poc_trust_list | grep -Fxq "$name"; then
    echo "  $name: already trusted, skipping (avoids the auth prompt)"
    return 0
  fi
  for i in 1 2; do
    if poc_trust_add "$ca" 2>/tmp/trusterr.txt; then
      echo "  $name: trusted"
      return 0
    fi
    # Seen intermittently right after make-pki.sh regenerated the CA: trustd has not
    # indexed the freshly added certificate yet, so the trust add cannot attach to it.
    [ "$i" = 1 ] && { echo "  $name: first attempt failed, retrying after a short pause"; sleep 3; }
  done
  echo "  $name: FAILED to trust:" >&2
  sed 's/^/    /' /tmp/trusterr.txt >&2
  return 1
}
# trustd indexes a certificate shortly after it lands in a keychain, so a verify
# immediately after add-certificates can fail spuriously. Give it a moment.
sleep 1

if verify_trust; then
  echo "  chain already verifies; no trust settings touched"
else
  # Trust settings are keyed to the certificate, so re-running make-pki.sh leaves
  # settings pointing at a previous CA generation with the same subject name. Those
  # stale entries are what make a re-add raise an authentication prompt, so clear ours
  # first and then add fresh -- a first-time add does not prompt.
  echo "  chain does not verify; clearing this POC's trust entries and adding them fresh"
  poc_trust_drop || echo "    (could not rewrite trust settings; continuing)"
  trust_ca pki/ca1/ca.crt
  trust_ca pki/ca2/ca.crt
fi
security dump-trust-settings 2>&1 | sed 's/^/  /' || true

echo "== verification =="
if verify_trust; then
  echo "  signerA chains to a trusted root: ok"
else
  echo "  signerA still does not verify after re-trusting." >&2
  echo "  Try ./teardown.sh, then make-pki.sh, then setup-trust.sh." >&2
  exit 1
fi

echo "== signing identity keychain =="
security delete-keychain "$SIGNKC" 2>/dev/null || true
security create-keychain -p "$KCPW" "$SIGNKC"
security set-keychain-settings -lut 21600 "$SIGNKC"
security unlock-keychain -p "$KCPW" "$SIGNKC"
for n in signerA signerB signerC; do
  security import "work/p12/$n.p12" -k "$SIGNKC" -P "$KCPW" -A -f pkcs12
done
# Re-adding a certificate that is already present is an error; it is also harmless.
security add-certificates -k "$SIGNKC" pki/ca1/ca.crt pki/ca2/ca.crt 2>/dev/null || true

# Without the codesign: partition entry, codesign fails with errSecInternalComponent.
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KCPW" "$SIGNKC" >/dev/null

echo "== search list =="
# Additive, so both PKI flows can coexist in either run order. `codesign --keychain`
# alone is not enough: a keychain missing from the search list makes codesign report
# "no identity found" even when it is passed explicitly.
poc_keychain_ensure_login
poc_keychain_add "$SIGNKC"
poc_keychain_list | sed 's/^/  /'

echo
echo "== identities =="
security find-identity -p codesigning "$SIGNKC"
echo
echo "Keychain passwords are the literal string: $KCPW"
