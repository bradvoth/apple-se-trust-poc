#!/bin/bash
# Are X.509 name constraints a usable extra control on the team CA?
#
# The idea: constrain a team's intermediate CA so it can only issue into that team's
# branch of the DN space. Then a compromise or a mistake in one team's CA cannot mint
# a certificate that looks like another team's -- which is exactly the "accidentally
# included" risk. Verified conclusion is in the README; the short version is that
# macOS DOES enforce name constraints, but not in an order Apple's DN convention allows.
set -uo pipefail
cd "$(dirname "$0")"
WORK=$(mktemp -d)

command -v openssl >/dev/null || { echo "openssl required"; exit 1; }

echo "== trying to constrain the Team B intermediate to OU=TEAMB =="
cat > "$WORK/nc.cnf" <<'EOF'
[ req ]
default_bits = 3072
prompt = no
distinguished_name = dn
x509_extensions = v3
[ dn ]
CN = POC Team B Intermediate CA (name constrained)
O = POC Enterprise
C = US
[ v3 ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
nameConstraints = critical, permitted;dirName:subtree
[ subtree ]
OU = TEAMB
EOF
openssl req -new -newkey rsa:3072 -nodes -keyout "$WORK/nc.key" -out "$WORK/nc.csr" \
  -config "$WORK/nc.cnf" 2>/dev/null
openssl x509 -req -in "$WORK/nc.csr" -CA pki/ent/ent-root.crt -CAkey pki/ent/ent-root.key \
  -CAcreateserial -days 1825 -sha256 -extfile "$WORK/nc.cnf" -extensions v3 \
  -out "$WORK/nc.crt" 2>/dev/null
openssl x509 -in "$WORK/nc.crt" -noout -text 2>/dev/null | grep -A3 "Name Constraints" | sed 's/^/  /'

issue() { # $1=subj  $2=out
  openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/$2.key" -out "$WORK/$2.csr" \
    -subj "$1" 2>/dev/null
  openssl x509 -req -in "$WORK/$2.csr" -CA "$WORK/nc.crt" -CAkey "$WORK/nc.key" \
    -CAcreateserial -days 1095 -sha256 -extfile pki/leaf.cnf -extensions v3_leaf \
    -out "$WORK/$2.crt" 2>/dev/null
}

# Apple's convention puts CN first, the team identifier (OU) second.
issue "/CN=POC Signing TeamB-ok/OU=TEAMB/O=POC Enterprise/C=US"   apple_ok
issue "/CN=POC Signing TeamB-rogue/OU=TEAMA/O=POC Enterprise/C=US" apple_bad
# Reordered so the constraining attribute is the leading RDN.
issue "/OU=TEAMB/CN=POC Signing TeamB-ok/O=POC Enterprise/C=US"    ou_first_ok
issue "/OU=TEAMA/CN=POC Signing TeamB-rogue/O=POC Enterprise/C=US" ou_first_bad

echo
echo "=== openssl verify ==="
for n in apple_ok apple_bad ou_first_ok ou_first_bad; do
  r=$(openssl verify -CAfile pki/ent/ent-root.crt -untrusted "$WORK/nc.crt" "$WORK/$n.crt" 2>&1)
  case "$r" in
    *": OK"*)                      printf '  %-14s accepted\n' "$n";;
    *"permitted subtree violation"*) printf '  %-14s REJECTED (permitted subtree violation)\n' "$n";;
    *)                             printf '  %-14s other: %s\n' "$n" "$(echo "$r" | tail -1)";;
  esac
done

echo
echo "=== macOS verify-cert (codeSign policy) ==="
# teamBnc must be findable for the chain to build.
LOGIN="$HOME/Library/Keychains/login.keychain-db"
security add-certificates -k "$LOGIN" "$WORK/nc.crt" 2>/dev/null || true
for n in apple_ok apple_bad ou_first_ok ou_first_bad; do
  r=$(security verify-cert -p codeSign -c "$WORK/$n.crt" 2>&1)
  case "$r" in
    *"successful"*)           printf '  %-14s accepted\n' "$n";;
    *INVALID_CERTIFICATE*)    printf '  %-14s REJECTED (CSSMERR_TP_INVALID_CERTIFICATE)\n' "$n";;
    *)                        printf '  %-14s %s\n' "$n" "$(echo "$r" | tail -1)";;
  esac
done
# remove the throwaway intermediate we just added to the login keychain
security delete-certificate -c "POC Team B Intermediate CA (name constrained)" "$LOGIN" >/dev/null 2>&1 || true

echo
echo "FINDING: a permitted dirName subtree must be a PREFIX of the subject's RDN"
echo "sequence. Apple's DN convention is CN-first, team identifier second, so a"
echo "constraint on OU can never be an ancestor of such a DN -- every leaf fails,"
echo "including correct ones. Only a reordered DN (OU first) can be constrained,"
echo "and macOS does enforce it there. So name constraints are real but are not"
echo "usable alongside Apple's DN ordering; the 'certificate 1' pin is what isolates"
echo "a team in practice."
rm -rf "$WORK"
