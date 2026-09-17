#!/bin/bash
# The decisive test: put each requirement candidate into a real keychain item ACL and
# check which callers actually get the key. The requirement evaluator and the keychain
# ACL have disagreed before in this POC (see the 'anchor trusted' finding), so the
# isolated requirement matrix is not sufficient evidence on its own.
set -uo pipefail
cd "$(dirname "$0")"
TESTKC="$PWD/work/poc-test-tiered.keychain-db"
KPW=poc
S='identifier "com.poc.client"'

ENT=$(openssl x509 -in pki/ent/ent-root.crt -outform DER | shasum -a 1 | cut -d' ' -f1)
TEA=$(openssl x509 -in pki/ent/teamA.crt    -outform DER | shasum -a 1 | cut -d' ' -f1)

security delete-keychain "$TESTKC" 2>/dev/null || true
security create-keychain -p "$KPW" "$TESTKC"
security set-keychain-settings -lut 21600 "$TESTKC"
security unlock-keychain -p "$KPW" "$TESTKC"
security list-keychains -d user -s "$HOME/Library/Keychains/login.keychain-db" \
  "$PWD/work/poc-signing-tiered.keychain-db" "$TESTKC"

# Keys are (re)created rather than reused: a key whose ACL is replaced in place keeps
# its original cdhash entry, which has misled this POC before.
echo "== creating keys =="
./bin/pocsetup mkkeyreq "$TESTKC" pin-teamA-via-cert1 \
  "$S and certificate 1 = H\"$TEA\"" >/dev/null 2>&1 \
  && echo "  pin-teamA-via-cert1" || echo "  pin-teamA-via-cert1 FAILED"
./bin/pocsetup mkkeyreq "$TESTKC" pin-teamA-via-OU \
  "$S and certificate leaf[subject.OU] = \"TEAMA\"" >/dev/null 2>&1 \
  && echo "  pin-teamA-via-OU" || echo "  pin-teamA-via-OU FAILED"
./bin/pocsetup mkkeyreq "$TESTKC" pin-enterprise-root \
  "$S and certificate root = H\"$ENT\"" >/dev/null 2>&1 \
  && echo "  pin-enterprise-root" || echo "  pin-enterprise-root FAILED"

KEYS=(pin-teamA-via-cert1 pin-teamA-via-OU pin-enterprise-root)
BINS=(teamA1 teamA2 teamB1)

echo
echo "=================== KEYCHAIN ACL MATRIX ==================="
printf '%-9s' "caller"
for k in "${KEYS[@]}"; do printf '%-24s' "$k"; done
echo
for b in "${BINS[@]}"; do
  printf '%-9s' "$b"
  for k in "${KEYS[@]}"; do
    out=$(./bin/pocclient-$b "$TESTKC" "$k" 2>&1)
    case "$out" in
      *GRANTED*)       r="GRANTED";;
      *DENIED_USE*)    r="deny-use";;
      *DENIED_LOOKUP*) r="deny-lookup";;
      *)               r="?";;
    esac
    printf '%-24s' "$r"
  done
  echo
done
echo
echo "The team-A pins should admit teamA1 and teamA2 and refuse teamB1."
echo "The enterprise-root pin is expected to admit ALL THREE -- that is the risk."
security delete-keychain "$TESTKC" 2>/dev/null || true
