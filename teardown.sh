#!/bin/bash
# Undo everything this POC did to the machine:
#   - remove the POC code-signing trust settings
#   - remove the POC CA certificates from the login keychain
#   - restore the keychain search list to the login keychain alone
#   - delete the POC keychains
# Generated files under pki/, bin/ and work/ are left in place.
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
# shellcheck source=lib-trust.sh
. "$ROOT/lib-trust.sh"
POC_ROOT="$ROOT"
LOGIN="$HOME/Library/Keychains/login.keychain-db"

echo "== remove trust settings =="
tl=$(poc_trust_list)
if [ -n "$tl" ]; then
  poc_trust_drop || echo "  could not rewrite trust settings; leaving them alone"
else
  echo "  none present"
fi
echo "  remaining:"
security dump-trust-settings 2>&1 | sed 's/^/    /' || true

echo "== remove CA certificates from the login keychain =="
# Delete by SHA-1, not by common name. `security delete-certificate -c` requires the
# name to match exactly one certificate, and repeated make-pki.sh runs leave several
# generations sharing a CN, which makes every deletion fail as "ambiguous". The hash
# is unique, and enumerating labels rather than using a fixed CN list also catches the
# intermediates that make-pki-tiered.sh adds.
hashes=$(security find-certificate -a -Z "$LOGIN" 2>/dev/null | awk '
  /^SHA-1 hash: / { h = $3 }
  /"labl"/        { if (match($0, /="POC[^"]*"/)) print h }
')
n=0
for h in $hashes; do
  security delete-certificate -Z "$h" "$LOGIN" >/dev/null 2>&1 && n=$((n + 1))
done
echo "  removed $n POC certificate(s)"

echo "== restore keychain search list =="
security list-keychains -d user -s "$LOGIN"
security list-keychains -d user | sed 's/^/  /'

echo "== delete POC keychains =="
for kc in "$ROOT/work/poc-signing.keychain-db" "$ROOT/work/poc-test.keychain-db" \
          "$ROOT/work/poc-signing-tiered.keychain-db" "$ROOT/work/poc-test-tiered.keychain-db"; do
  security delete-keychain "$kc" 2>/dev/null && echo "  removed $kc" || echo "  (absent) $kc"
done

echo "== signing identities remaining =="
security find-identity -v -p codesigning 2>&1 | sed 's/^/  /'
echo "done"
