#!/bin/bash
# Does APPROVING the keychain prompt actually grant access to a key whose ACL
# requirement the caller fails?
#
# This is load-bearing for the claim that the ACL is "user-mediated rather than
# enforced": that claim holds only if approving the dialog hands over the key. The
# prompt subject lives in the closed-source daemon, so this settles it empirically.
#
# It displays a real dialog and answers it. It answers only its own test key.
#
# Usage: ./run-prompt-approval.sh
set -uo pipefail
cd "$(dirname "$0")"
. "$PWD/lib-trust.sh"

TESTKC="$PWD/work/poc-test.keychain-db"
KCPW=poc
CA1=$(openssl x509 -in pki/ca1/ca.crt -outform DER | shasum -a 1 | cut -d' ' -f1)

[ -f "$TESTKC" ] || { echo "run ./setup-trust.sh and ./make-keys.sh first"; exit 1; }
security unlock-keychain -p "$KCPW" "$TESTKC" >/dev/null 2>&1
poc_keychain_add "$TESTKC"

# A key whose requirement ONLY signedA satisfies, so signedB is a genuine
# non-matching caller. Pinning the CA1 root would NOT work here: signedB is also
# issued by CA1, so a root pin admits it and the test would silently pass.
LEAF_A=$(openssl x509 -in pki/leaves/signerA.crt -outform DER | shasum -a 1 | cut -d' ' -f1)
KEY=prompt-approval-test
REQ="identifier \"com.poc.client\" and certificate leaf = H\"$LEAF_A\""

# Pre-flight: assert the premise, so an invalid control cannot look like a result.
if ./bin/pocsetup checkreq "$REQ" bin/pocclient-signedA >/dev/null 2>&1; then
  echo "premise ok: signedA satisfies the requirement"
else
  echo "premise FAILED: signedA does not satisfy the requirement"; exit 1
fi
if ./bin/pocsetup checkreq "$REQ" bin/pocclient-signedB >/dev/null 2>&1; then
  echo "premise FAILED: signedB also satisfies the requirement (test would be vacuous)"; exit 1
fi
echo "premise ok: signedB does not satisfy the requirement"
echo

security delete-generic-password -l "$KEY" >/dev/null 2>&1
./bin/pocsetup mkkeyreq "$TESTKC" "$KEY" "$REQ" >/dev/null 2>&1 || {
    echo "key creation failed"; exit 1; }
echo "created key '$KEY' pinned to signedA's leaf certificate"
echo

approve_and_observe() {
  # Run the non-matching caller with UI ENABLED, approve the dialog, and report
  # whether it then obtains the key.
  POC_ALLOW_UI=1 ./bin/pocclient-signedB "$TESTKC" "$KEY" >/tmp/pa-out.txt 2>&1 &
  local pid=$!
  local waited=0 nowin=0
  while kill -0 $pid 2>/dev/null; do
    sleep 0.5; waited=$((waited + 1))
    if pgrep -x SecurityAgent >/dev/null 2>&1; then
      local n
      n=$(osascript -e 'tell application "System Events" to tell process "SecurityAgent" to get count of windows' 2>/dev/null)
      if [ "${n:-0}" != "0" ] && [ "$nowin" = "0" ]; then
        echo "  dialog appeared after ~${waited}00ms:"
        osascript -e 'tell application "System Events" to tell process "SecurityAgent" to tell window 1 to get value of every static text' 2>/dev/null | tr ',' '\n' | sed 's/^ */    /' | head -6
        echo "  buttons:"
        osascript -e 'tell application "System Events" to tell process "SecurityAgent" to tell window 1 to get name of every button' 2>/dev/null | tr ',' '\n' | sed 's/^ */    /'
        nowin=1
        echo "  --- supplying the keychain password and clicking Allow ---"
        # The dialog requires the keychain password, not just a click: approving is an
        # explicit credential presentation. Fill the field, then choose one-time Allow
        # (preferring it over "Always Allow", which would persist this binary in the ACL
        # and change stored state).
        KCPW="$KCPW" osascript <<'APPLESCRIPT' 2>&1 | sed 's/^/    /'
tell application "System Events"
  tell process "SecurityAgent"
    set kcpw to system attribute "KCPW"
    try
      set value of text field 1 of window 1 to kcpw
    on error errMsg
      return "could not fill password field: " & errMsg
    end try
    delay 0.5
    set btns to name of every button of window 1
    repeat with b in btns
      set bn to b as text
      if bn is "Allow" or bn is "OK" then
        click button bn of window 1
        return "filled password and clicked (one-time): " & bn
      end if
    end repeat
    repeat with b in btns
      set bn to b as text
      if bn is not "Cancel" and bn is not "Deny" then
        click button bn of window 1
        return "filled password and clicked (fallback, may persist): " & bn
      end if
    end repeat
  end tell
end tell
APPLESCRIPT
      fi
    fi
    [ $waited -ge 40 ] && break
  done
  if kill -0 $pid 2>/dev/null; then
    echo "  client still running; killing it"
    kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null
    echo "  OUTCOME: did not complete"
  else
    wait $pid 2>/dev/null
    echo "  client exited; output:"
    sed 's/^/    /' /tmp/pa-out.txt
    case "$(cat /tmp/pa-out.txt)" in
      *GRANTED*)       echo "  OUTCOME: *** APPROVAL GRANTED ACCESS ***";;
      *DENIED_USE*)    echo "  OUTCOME: approval did NOT grant access (denied)";;
      *DENIED_LOOKUP*) echo "  OUTCOME: approval did NOT grant access (lookup denied)";;
      *)               echo "  OUTCOME: indeterminate";;
    esac
  fi
  pkill -9 -x pocclient-signedB 2>/dev/null
  sleep 1
  pkill -x SecurityAgent 2>/dev/null
  sleep 1
}

approve_and_observe

echo
echo "cleanup:"
security delete-generic-password -l "$KEY" >/dev/null 2>&1
./bin/rmkeys "$KEY" >/dev/null 2>&1
echo "  key '$KEY' removed"
pgrep -x SecurityAgent >/dev/null && echo "  WARNING: SecurityAgent still present" || echo "  no SecurityAgent windows remain"
