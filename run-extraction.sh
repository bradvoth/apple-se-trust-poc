#!/bin/bash
# Separate the two questions the ACL answers: may this caller USE the key, and may it
# TAKE the key material? A pin that authorises Sign does not automatically authorise
# ExportClear, and the storage layer is a third path that consults neither.
set -uo pipefail
cd "$(dirname "$0")"
. "$PWD/lib-trust.sh"

TESTKC="$PWD/work/poc-test.keychain-db"
[ -f "$TESTKC" ] || { echo "run ./setup-trust.sh and ./make-keys.sh first"; exit 1; }
./build.sh >/dev/null 2>&1
poc_keychain_add "$TESTKC"

echo "=============================================================="
echo " Use versus extraction, for a key pinned to signedA's leaf"
echo "=============================================================="
echo "(the probe is unsigned, so it matches no requirement in the ACL)"
echo
./bin/pocexport "$TESTKC" pin-leaf-a

echo
echo "=============================================================="
echo " The default ACL from SecAccessCreate grants export"
echo "=============================================================="
echo "make-keys.sh builds ACLs by stripping SecAccessCreate's defaults and then adding"
echo "only a Sign/Decrypt entry. A key built without that step keeps the defaults, which"
echo "include ExportClear -- so the absence of an export right above is a property of how"
echo "the ACL was constructed, not of pinning in general."

echo
echo "=============================================================="
echo " Item-type differences worth knowing"
echo "=============================================================="
echo "- Security denies -25293 (CSSMERR_CSP_OPERATION_AUTH_DENIED) for both Sign and"
echo "  ExportClear on a pinned key, because no ACL entry authorizes export at all."
echo "- The key material still lives in the keychain container. Anyone who can open the"
echo "  container -- the user's own password, or root reading /var/db/SystemKey -- has it"
echo "  and no ACL is consulted on that path. This is the exposure a Secure Enclave key"
echo "  removes: the key is generated in and never leaves the SEP."
