#!/bin/bash
# Demonstrates the prompt fallback: with keychain UI ENABLED, a caller that does
# NOT satisfy the pinned requirement gets a SecurityAgent dialog instead of a
# denial, and blocks until the user answers.
#
# This puts real dialogs on screen. It is behind a flag on purpose. If a caller
# hangs, the script kills it, but a dialog may outlive the process.
#
# For a non-interactive view of the same thing, use ./run-aclstruct.sh, which
# reads the stored ACL's subject structure out of the securityd log and shows the
# KeychainPromptAclSubject without ever prompting.
#
# Usage: ./run-promptcheck.sh --yes-show-dialogs
set -uo pipefail
cd "$(dirname "$0")"

if [ "${1:-}" != "--yes-show-dialogs" ]; then
  cat <<'EOF'
Refusing to run: this test displays real keychain approval dialogs.

Use ./run-aclstruct.sh instead for a non-interactive equivalent, or re-run as:

    ./run-promptcheck.sh --yes-show-dialogs

If a dialog does appear, you can dismiss it with Escape. Killing the process does
not necessarily dismiss its dialog.
EOF
  exit 1
fi

TESTKC="$PWD/work/poc-test.keychain-db"

cleanup() { pkill -9 -x pocclient 2>/dev/null; sleep 0.5; pkill -x SecurityAgent 2>/dev/null; }
trap cleanup EXIT

try() { # $1=binary  $2=key
  local i=0 rc
  POC_ALLOW_UI=1 ./bin/pocclient-$1 "$TESTKC" "$2" >/tmp/pp.txt 2>&1 &
  local p=$!
  while kill -0 $p 2>/dev/null && [ $i -lt 10 ]; do sleep 0.5; i=$((i+1)); done
  if kill -0 $p 2>/dev/null; then
    kill -9 $p 2>/dev/null; wait $p 2>/dev/null; rc="PROMPTED(waiting on user)"
  else
    wait $p; rc="finished exit=$?"
  fi
  local res="?"
  case "$(cat /tmp/pp.txt)" in
    *GRANTED*)     res="GRANTED";;
    *DENIED_USE*)  res="DENIED_USE";;
    *DENIED_LOOKUP*) res="DENIED_LOOKUP";;
  esac
  printf '%-9s %-14s %-22s %s\n' "$1" "$2" "$res" "$rc"
  cleanup
}

echo "caller    key            result                 outcome"
echo "--- callers that DO satisfy the requirement ---"
try signedA pin-root-ca1
try signedB pin-leaf-b
echo "--- callers that do NOT satisfy it ---"
try unsigned pin-root-ca1
try adhoc    pin-root-ca1
try signedB  pin-leaf-a
try signedC  pin-root-ca1
echo
echo "Anything reported as PROMPTED is a caller the ACL refused, that still got a"
echo "dialog and would have had the key had the user approved it."
