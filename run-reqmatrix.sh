#!/bin/bash
# Evaluate each candidate requirement against each binary, independent of the
# keychain, using SecStaticCodeCheckValidity (the same machinery the keychain
# ACL uses via SecTrustedApplicationValidateWithPath).
set -uo pipefail
cd "$(dirname "$0")"
CA1=$(openssl x509 -in pki/ca1/ca.crt -outform DER | shasum -a 1 | cut -d' ' -f1)
LEAF_A=$(openssl x509 -in pki/leaves/signerA.crt -outform DER | shasum -a 1 | cut -d' ' -f1)

S='identifier "com.poc.client"'
REQS=(
  "$S and certificate root = H\"$CA1\"|pin-root-ca1"
  "$S and certificate leaf = H\"$LEAF_A\"|pin-leaf-a (Signing A)"
  "$S and anchor trusted|anchor trusted"
  "$S and anchor apple|anchor apple"
  "$S|identifier only"
  "$S and certificate root[subject.CN] = \"POC Private Root CA 1\"|pin CA1 by subject CN"
  "$S and certificate leaf[subject.OU] = \"POC1\"|pin team/OU POC1 (Apple-style)"
  "$S and certificate leaf[subject.OU] = \"POC2\"|pin team/OU POC2"
)
BINS=(unsigned adhoc signedA signedB signedC)

printf '%-38s' "requirement"
for b in "${BINS[@]}"; do printf '%-9s' "$b"; done
echo
for r in "${REQS[@]}"; do
  req="${r%|*}"; name="${r#*|}"
  printf '%-38s' "${name:0:37}"
  for b in "${BINS[@]}"; do
    if ./bin/pocsetup checkreq "$req" "bin/pocclient-$b" >/dev/null 2>&1; then printf '%-9s' "MATCH"; else printf '%-9s' "."; fi
  done
  echo
done
echo
echo "(. = no match)"
