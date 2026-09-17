#!/bin/bash
# Sign the client with each team's certificate, so we can compare which requirement
# forms pin "team A" versus "the whole enterprise".
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=lib-trust.sh
. "$PWD/lib-trust.sh"
KC="$PWD/work/poc-signing-tiered.keychain-db"

# codesign --keychain still needs the keychain in the search list.
poc_keychain_add "$KC"

./build.sh >/dev/null

sign_one() { # $1=binary suffix  $2=identity CN
  cp bin/pocclient "bin/pocclient-$1"
  codesign --keychain "$KC" -s "$2" -i com.poc.client -f "bin/pocclient-$1"
}

sign_one teamA1 "POC Signing TeamA-1"
sign_one teamA2 "POC Signing TeamA-2"
sign_one teamB1 "POC Signing TeamB-1"

echo
printf '%-24s %s\n' BINARY "EMBEDDED CHAIN (Authority lines, leaf first)"
for b in teamA1 teamA2 teamB1; do
  printf '%-24s\n' "pocclient-$b"
  codesign -dvvv "bin/pocclient-$b" 2>&1 | grep '^Authority=' | sed 's/^Authority=/    /'
done

echo
printf '%-24s %s\n' BINARY "DERIVED DESIGNATED REQUIREMENT"
for b in teamA1 teamA2 teamB1; do
  dr=$(codesign -d -r- "bin/pocclient-$b" 2>/dev/null | sed -n 's/^designated => //p')
  printf '%-24s %s\n' "pocclient-$b" "$dr"
done
