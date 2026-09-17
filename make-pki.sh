#!/bin/bash
# Generate the PKI: two self-signed CAs and three code-signing leaf certificates.
# CA1 is "ours"; CA2 plays the part of a different certificate chain that is also
# trusted, so we can test "trusted, but not by the pinned signer".
set -euo pipefail
cd "$(dirname "$0")"

# Regenerating a CA invalidates any trust setting that references it, and establishing trust
# again requires an interactive Touch ID / password dialog that would block an unattended run.
# So this script is idempotent: if the CA already exists and is consistent with the leaves, it
# does nothing unless POC_FORCE_PKI_REGEN=1 is set.
if [ -f "pki/ca1/ca.crt" ] && [ "${POC_FORCE_PKI_REGEN:-0}" != "1" ]; then
    # Only skip when the leaves actually chain to the existing CA.
    if openssl verify -CAfile pki/ca1/ca.crt pki/leaves/signerA.crt >/dev/null 2>&1; then
        echo "== PKI already present and consistent; not regenerating =="
        echo "   (set POC_FORCE_PKI_REGEN=1 to rebuild, but note this invalidates trust)"
        exit 0
    fi
fi


mkdir -p pki/ca1 pki/ca2 pki/leaves work/p12

echo "== CA1 (ours) =="
openssl req -x509 -newkey rsa:3072 -nodes -days 1825 \
  -keyout pki/ca1/ca.key -out pki/ca1/ca.crt -config pki/ca1/ca.cnf 2>/dev/null

echo "== CA2 (rogue, also trusted) =="
openssl req -x509 -newkey rsa:3072 -nodes -days 1825 \
  -keyout pki/ca2/ca.key -out pki/ca2/ca.crt -config pki/ca2/ca.cnf 2>/dev/null

mkleaf() { # $1=cadir  $2=name  $3=CN  $4=OU (stands in for an Apple Team ID)
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "pki/leaves/$2.key" -out "work/$2.csr" \
    -subj "/CN=$3/OU=$4/O=POC Apple Signing/C=US" 2>/dev/null
  openssl x509 -req -in "work/$2.csr" -CA "$1/ca.crt" -CAkey "$1/ca.key" -CAcreateserial \
    -days 1095 -sha256 -extfile pki/leaf.cnf -extensions v3_leaf \
    -out "pki/leaves/$2.crt" 2>/dev/null
  openssl pkcs12 -export -inkey "pki/leaves/$2.key" -in "pki/leaves/$2.crt" \
    -name "$2" -out "work/p12/$2.p12" -passout pass:poc -legacy 2>/dev/null
}

echo "== leaf certificates =="
mkleaf pki/ca1 signerA "POC Software Signing A" POC1
mkleaf pki/ca1 signerB "POC Software Signing B" POC1
mkleaf pki/ca2 signerC "Rogue Software Signing C" POC2

for n in signerA signerB signerC; do
  printf '  %-9s %s\n' "$n" "$(openssl x509 -in pki/leaves/$n.crt -noout -subject | tr '\n' ' ')"
done
echo "done"
