#!/bin/bash
# Show how an Apple Developer ID signature is actually put together, using an
# installed app as the example. This is the same shape as our private-CA setup,
# with Apple in the role our CA plays.
#
# Usage: ./run-profile.sh [path-to-.app]     (default: 1Password or Claude)
set -uo pipefail
APP="${1:-}"
if [ -z "$APP" ]; then
  for c in /Applications/1Password.app /Applications/Claude.app /Applications/Steam.app; do
    [ -d "$c" ] && { APP="$c"; break; }
  done
fi
[ -n "$APP" ] && [ -d "$APP" ] || { echo "no Developer ID app found; pass a path"; exit 1; }

echo "=============================================================="
echo " app: $APP"
echo "=============================================================="

echo
echo "--- 1. the signing chain (who certified this code) ---"
codesign -dvvv "$APP" 2>&1 | grep -E "^(Identifier|TeamIdentifier|Authority|Timestamp)=" | sed 's/^/  /'

echo
echo "--- 2. the designated requirement (what Apple itself pins to) ---"
codesign -d -r- "$APP" 2>&1 | sed -n 's/^designated => /  /p' | fold -w 100 -s | sed 's/^/  /'
echo
echo "  Note two things: 'anchor apple generic' pins a chain to Apple, and"
echo "  'certificate leaf[subject.OU]' pins the TEAM ID rather than the certificate"
echo "  hash. Developer ID leaf certificates are reissued on renewal, so pinning the"
echo "  hash would break every time one rotates. Pinning the team ID does not."

echo
echo "--- 3. the embedded provisioning profile (the binding document) ---"
PP="$APP/Contents/embedded.provisionprofile"
if [ ! -f "$PP" ]; then
  echo "  (no embedded.provisionprofile; this app needs no restricted entitlements)"
else
  TMP=$(mktemp)
  if security cms -D -i "$PP" -o "$TMP" 2>/dev/null; then
    plutil -p "$TMP" 2>/dev/null | sed -n \
      -e '/"TeamIdentifier" =>/,/^  }/p' \
      -e '/"Entitlements" => {/,/^  }/p' | sed 's/^/  /'
    echo "  DeveloperCertificates listed: $(plutil -p "$TMP" 2>/dev/null | grep -c 'length =')"
    echo
    echo "  The profile is signed by Apple. AMFI checks, in order: that the binary's"
    echo "  signature chains to Apple, that its signing certificate appears in"
    echo "  DeveloperCertificates, and that the profile grants the entitlement being"
    echo "  claimed. That is the whole mechanism -- there is no secret beyond it."
  else
    echo "  (could not decode the profile)"
  fi
  rm -f "$TMP"
fi

echo
echo "--- 4. which keychain model this identity can use ---"
echo "  keychain-access-groups is team-prefixed in the profile above, e.g."
echo "  Q6L2SF6YDW.* -- so data-protection-keychain (and therefore Secure Enclave)"
echo "  items are scoped to the TEAM, not to one binary. Every app your team signs"
echo "  can claim a group under that prefix; no other team can claim it at all."
echo
echo "  Contrast with the file-keychain ACL this POC uses, which is scoped per"
echo "  binary by a code requirement (kSecAttrAccess / CCSM ACL). The two are"
echo "  different keychains with different authorization models:"
echo "    legacy file keychain  -> kSecAttrAccess       (code requirement, no entitlement)"
echo "    data protection kc    -> kSecAttrAccessGroup  (team access group, restricted entitlement)"
