#!/bin/bash
# Build a two-tier PKI, which is what an enterprise deployment would actually look
# like: one enterprise root, a sub-CA per team, and that team's sub-CA issuing the
# signing certificates.
#
#   POC Enterprise Root  (self-signed, pathlen:1)
#     +-- POC Team A Intermediate CA  (pathlen:0)  -> teamA1, teamA2
#     +-- POC Team B Intermediate CA  (pathlen:0)  -> teamB1
#
# The point of the exercise is to find out which requirement form actually pins
# "team A and not team B", because the chain is now three deep and 'certificate
# root' does not mean what it looks like it means.
set -euo pipefail
cd "$(dirname "$0")"

# Regenerating a CA invalidates any trust setting that references it, and establishing trust
# again requires an interactive Touch ID / password dialog that would block an unattended run.
# So this script is idempotent: if the CA already exists and is consistent with the leaves, it
# does nothing unless POC_FORCE_PKI_REGEN=1 is set.
if [ -f "pki/ent/ent-root.crt" ] && [ "${POC_FORCE_PKI_REGEN:-0}" != "1" ]; then
    # Only skip when the leaves actually chain to the existing CA.
    if openssl verify -CAfile pki/ent/ent-root.crt pki/leaves3/teamA1.crt >/dev/null 2>&1; then
        echo "== PKI already present and consistent; not regenerating =="
        echo "   (set POC_FORCE_PKI_REGEN=1 to rebuild, but note this invalidates trust)"
        exit 0
    fi
fi


mkdir -p pki/ent pki/leaves3 work/p12-3

echo "== enterprise root =="
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
  -keyout pki/ent/ent-root.key -out pki/ent/ent-root.crt \
  -config pki/ent/ent.cnf 2>/dev/null

mkinter() { # $1=name  $2=cnf
  # A sub-CA is created as a CSR and signed by the enterprise root.
  openssl req -new -newkey rsa:3072 -nodes \
    -keyout "pki/ent/$1.key" -out "work/$1.csr" -config "$2" 2>/dev/null
  openssl x509 -req -in "work/$1.csr" \
    -CA pki/ent/ent-root.crt -CAkey pki/ent/ent-root.key -CAcreateserial \
    -days 1825 -sha256 -extfile "$2" -extensions v3_intermediate \
    -out "pki/ent/$1.crt" 2>/dev/null
}

echo "== team intermediates (signed by the enterprise root) =="
mkinter teamA pki/ent/teamA.cnf
mkinter teamB pki/ent/teamB.cnf

mkleaf() { # $1=team  $2=name  $3=CN  $4=OU
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "pki/leaves3/$2.key" -out "work/$2.csr" \
    -subj "/CN=$3/OU=$4/O=POC Enterprise/C=US" 2>/dev/null
  openssl x509 -req -in "work/$2.csr" \
    -CA "pki/ent/$1.crt" -CAkey "pki/ent/$1.key" -CAcreateserial \
    -days 1095 -sha256 -extfile pki/leaf.cnf -extensions v3_leaf \
    -out "pki/leaves3/$2.crt" 2>/dev/null
  openssl pkcs12 -export -inkey "pki/leaves3/$2.key" -in "pki/leaves3/$2.crt" \
    -certfile "pki/ent/$1.crt" \
    -name "$2" -out "work/p12-3/$2.p12" -passout pass:poc -legacy 2>/dev/null
}

echo "== signing leaves, issued per team =="
mkleaf teamA teamA1 "POC Signing TeamA-1" TEAMA
mkleaf teamA teamA2 "POC Signing TeamA-2" TEAMA
mkleaf teamB teamB1 "POC Signing TeamB-1" TEAMB

for f in pki/ent/ent-root.crt pki/ent/teamA.crt pki/ent/teamB.crt \
         pki/leaves3/teamA1.crt pki/leaves3/teamA2.crt pki/leaves3/teamB1.crt; do
  printf '  %-28s %s\n' "$(basename "$f")" \
    "$(openssl x509 -in "$f" -noout -subject | sed 's/subject=//')"
done
echo
echo "== SHA-1 of each CA, for the requirement comparisons =="
for f in pki/ent/ent-root.crt pki/ent/teamA.crt pki/ent/teamB.crt; do
  printf '  %-16s %s\n' "$(basename "$f" .crt)" \
    "$(openssl x509 -in "$f" -outform DER | shasum -a 1 | cut -d' ' -f1)"
done
echo
echo "== chain depth check =="
openssl verify -CAfile pki/ent/ent-root.crt -untrusted pki/ent/teamA.crt pki/leaves3/teamA1.crt
