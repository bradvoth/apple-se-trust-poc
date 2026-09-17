#!/bin/bash
# Secure Enclave evaluation: can an SE key replace the file-keychain ACL approach?
#
# Deliberately does NOT test the biometric gates (kSecAccessControlUserPresence /
# BiometryAny / DevicePasscode), because those put a Touch ID or password dialog on
# screen. Their semantics are documented rather than measured here.
set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=lib-trust.sh
. "$PWD/lib-trust.sh"
ROOT="$PWD"
KC="$ROOT/work/poc-signing.keychain-db"
ENT="$ROOT/work/se.entitlements"
TMP=$(mktemp -d)

echo "building pocse"
clang -fobjc-arc -O1 -Wno-deprecated-declarations -framework Foundation -framework Security \
  -o "$TMP/pocse" tools/pocse.m || exit 1
clang -fobjc-arc -O1 -Wno-deprecated-declarations -framework Foundation -framework Security \
  -o "$TMP/rmkeys" tools/rmkeys.m || exit 1

echo
echo "=============================================================="
echo " 1. Can a persistent Secure Enclave key be created at all?"
echo "=============================================================="
printf '  %-34s ' "persistent, data protection keychain"
( "$TMP/pocse" mk "se_p_$RANDOM" none >"$TMP/o" 2>&1 ) 2>/dev/null
printf 'exit=%-4s %s\n' "$?" "$(grep -oE 'error -[0-9]+[^)]*\)|create error -[0-9]+' "$TMP/o" | head -1 | cut -c1-40)"
printf '  %-34s ' "persistent, keychain left at default"
( "$TMP/pocse" mk "se_pd_$RANDOM" unset:none >"$TMP/o" 2>&1 ) 2>/dev/null
printf 'exit=%-4s %s\n' "$?" "$(grep -oE 'error -[0-9]+' "$TMP/o" | head -1)"
printf '  %-34s ' "persistent, legacy file keychain"
"$TMP/pocse" mk se_legacy_downgrade legacy:none >"$TMP/o" 2>&1
printf 'exit=%-4s %s\n' "$?" "$(grep -oE 'VERDICT:.*|error -[0-9]+' "$TMP/o" | head -1)"
# It is not in the Secure Enclave, but it IS a real, persistent, findable key --
# which is the trap: the request succeeds and the key material is on disk.
kg=$(security find-key 2>/dev/null || true)
case "$kg" in *'"se_legacy_downgrade"'*)
  printf '  %-34s %s\n' "" "and it PERSISTED in the keychain as a normal software key"
  ;;
esac
"$TMP/rmkeys" se_legacy_downgrade >/dev/null 2>&1
printf '  %-34s ' "ephemeral, nothing persisted"
( "$TMP/pocse" mk "se_e_$RANDOM" eph:none >"$TMP/o" 2>&1 ) 2>/dev/null
printf 'exit=%-4s %s\n' "$?" "$(grep -oE 'VERDICT:.*|error -[0-9]+' "$TMP/o" | head -1)"
echo
echo "  -34018 = errSecMissingEntitlement. See step 3 for what AMFI does about it."
echo "  Note the legacy row: no error, but the key is NOT in the Secure Enclave."

echo
echo "=============================================================="
echo " 2. Does using an SE key need a human present?"
echo "=============================================================="
for g in none privateusage; do
  printf '  gate=%-14s ' "$g"
  "$TMP/pocse" mkuse "se_u_$RANDOM" "$g" >"$TMP/o" 2>&1
  printf '%s\n' "$(grep -oE 'SIGN OK.*|SIGN FAILED.*|VERDICT:.*' "$TMP/o" | tr '\n' ' ')"
done
echo "  (gates that DO require a human: presence, biometry, passcode -- not tested here)"

echo
echo "=============================================================="
echo " 3. Restricted entitlements: what happens when you sign"
echo "    one in with only a private CA"
echo "=============================================================="
# codesign --keychain alone is not enough: without the keychain in the search list it
# reports "no identity found" and falls back to an AD-HOC signature, which would make
# this test silently meaningless (an ad-hoc binary is rejected for a different reason).
poc_keychain_add "$KC"

sign_or_die() { # $1=output  $2=entitlements (or "" for none)
  if [ -n "$2" ]; then
    codesign --force --keychain "$KC" --sign "POC Software Signing A" \
      --entitlements "$2" "$1" >/dev/null 2>&1
  else
    codesign --force --keychain "$KC" --sign "POC Software Signing A" "$1" >/dev/null 2>&1
  fi
  # Capture first, grep second. `codesign -dvvv | grep -q` looks fine but under
  # `set -o pipefail` it is a trap: grep -q exits at the first match, codesign dies of
  # SIGPIPE (141), and the pipeline reports failure even though the signature is
  # correct. Redirecting the output to a file avoids the pipe entirely.
  codesign -dvvv "$1" >"$TMP/authorities.txt" 2>&1
  if ! grep -q '^Authority=POC Software Signing A' "$TMP/authorities.txt"; then
    echo "  ERROR: $1 is not signed by our CA (codesign fell back?)" >&2
    return 1
  fi
}

cp "$TMP/pocse" "$TMP/pocse-ent-adhoc"; codesign --force --sign - \
  --entitlements "$ENT" "$TMP/pocse-ent-adhoc" >/dev/null 2>&1
cp "$TMP/pocse" "$TMP/pocse-ent-cert";  sign_or_die "$TMP/pocse-ent-cert" "$ENT" || exit 1
cp "$TMP/pocse" "$TMP/pocse-cert-noent"; sign_or_die "$TMP/pocse-cert-noent" "" || exit 1
# The whole loop in a subshell with stderr discarded, because a SIGKILLed child
# makes bash print a "Killed: 9" job-status line that is pure noise here.
(
for b in pocse-cert-noent pocse-ent-adhoc pocse-ent-cert; do
  "$TMP/$b" mk "se_e2_$$" none >"$TMP/o" 2>&1; rc=$?
  case $rc in
    137) note="KILLED AT LAUNCH (AMFI rejected the restricted entitlement)";;
    0)   note="ran, created key";;
    *)   note=$(grep -oE 'error -34018' "$TMP/o" | head -1); note="${note:-exit=$rc}";;
  esac
  printf '  %-22s exit=%-5s %s\n' "$b" "$rc" "$note"
done
) 2>/dev/null
echo
echo "  amfid's own words (from the unified log):"
log show --last 5m --predicate 'process == "amfid"' --style compact 2>/dev/null \
  | grep -oE '(Adhoc signed app with restricted entitlements detected|The file is adhoc signed but contains restricted entitlements|Unable to retrieve certificate chain)' \
  | sort -u | sed 's/^/    /' || true

echo
echo "=============================================================="
echo " 4. Can an SE key carry a code requirement instead of a"
echo "    protection class?  (the file-keychain mechanism)"
echo "=============================================================="
"$TMP/pocse" mkreq "se_r_$RANDOM" >"$TMP/o" 2>&1
echo "  $(grep -oE 'result: -?[0-9]+' "$TMP/o" | head -1)"
echo "  access control constraints actually stored:"
grep -A3 'constraints:' "$TMP/o" | sed 's/^/   /'
echo "  The code requirement is accepted without error and appears nowhere in the"
echo "  key's access control. SE access control expresses a protection class and"
echo "  presence gates only; there is no code-identity field."

rm -rf "$TMP"
