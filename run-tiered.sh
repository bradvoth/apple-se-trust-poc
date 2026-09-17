#!/bin/bash
# Which requirement form actually pins a team, now that the chain is three deep?
#
# The chain is: leaf -> team intermediate -> enterprise root, so:
#   certificate leaf == certificate 0 == the signing certificate
#   certificate 1                       == the TEAM INTERMEDIATE
#   certificate root == certificate 2   == the ENTERPRISE ROOT
#
# 'certificate root' is the trap: in a two-tier setup it was the CA you pinned, but
# in a three-tier setup it is the enterprise root and therefore matches every team.
set -uo pipefail
cd "$(dirname "$0")"
S='identifier "com.poc.client"'

ENT=$(openssl x509 -in pki/ent/ent-root.crt -outform DER | shasum -a 1 | cut -d' ' -f1)
TEA=$(openssl x509 -in pki/ent/teamA.crt    -outform DER | shasum -a 1 | cut -d' ' -f1)
TEB=$(openssl x509 -in pki/ent/teamB.crt    -outform DER | shasum -a 1 | cut -d' ' -f1)

echo "enterprise root  $ENT"
echo "team A intermed  $TEA"
echo "team B intermed  $TEB"
echo

REQS=(
"$S and certificate root = H\"$ENT\"|certificate root = enterprise root"
"$S and certificate root = H\"$TEA\"|certificate root = team A  <-- the trap"
"$S and certificate 1 = H\"$TEA\"|certificate 1 = team A"
"$S and certificate 1 = H\"$TEB\"|certificate 1 = team B"
"$S and certificate 2 = H\"$ENT\"|certificate 2 = enterprise root"
"$S and certificate 1[subject.CN] = \"POC Team A Intermediate CA\"|certificate 1 CN = Team A"
"$S and certificate 1[subject.CN] = \"POC Team B Intermediate CA\"|certificate 1 CN = Team B"
"$S and certificate leaf[subject.OU] = \"TEAMA\"|certificate leaf OU = TEAMA"
"$S and certificate leaf[subject.OU] = \"TEAMB\"|certificate leaf OU = TEAMB"
"$S and anchor apple generic|anchor apple generic"
"$S and anchor trusted|anchor trusted"
)

BINS=(teamA1 teamA2 teamB1)
printf '%-40s' "requirement"
for b in "${BINS[@]}"; do printf '%-9s' "$b"; done
echo
for r in "${REQS[@]}"; do
  req="${r%|*}"; name="${r#*|}"
  printf '%-40s' "${name:0:39}"
  for b in "${BINS[@]}"; do
    if ./bin/pocsetup checkreq "$req" "bin/pocclient-$b" >/dev/null 2>&1; then
      printf '%-9s' "MATCH"
    else
      printf '%-9s' "."
    fi
  done
  echo
done
echo
echo "MATCH = the requirement accepts that binary;  . = it rejects it"
echo
echo "Read the first three data rows together: pinning 'root' admits both teams,"
echo "pinning 'root = team A' admits nothing, and only 'certificate 1' isolates a team."
