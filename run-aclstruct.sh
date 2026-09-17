#!/bin/bash
# Ask securityd to evaluate each key's ACL (by making a request that fails) and
# read out the ACL's internal subject structure. This shows whether an entry
# carries a KeychainPromptAclSubject (a "ask the user" fallback) or only the
# code-signature subject.
set -uo pipefail
cd "$(dirname "$0")"
TESTKC="$PWD/work/poc-test.keychain-db"
LOG=/tmp/aclstruct.txt

: > "$LOG"
log stream --style compact --predicate 'process == "securityd"' > "$LOG" 2>&1 &
LOGPID=$!
sleep 3

for key in pin-root-ca1 pin-leaf-a hard-pin-ca1; do
  # signedC does not satisfy any of these; UI stays disabled so nothing appears.
  ./bin/pocclient-signedC "$TESTKC" "$key" >/dev/null 2>&1
  sleep 1
done
sleep 3
kill $LOGPID 2>/dev/null

echo "=== ACL subject structure as securityd sees it ==="
grep -o "ObjectAcl REJECTS access using ACL:.*" "$LOG" \
  | sed -e 's/.*SUBJECT\[//' -e 's/\]>\]* *\]>//' \
  | grep -o "CodeSignatureAclSubject\[[^]]*\][^]]*" \
  | sed -e 's/\[legacyHash:[0-9a-f]*\]//' \
  | sort -u
echo
echo "=== does any evaluated entry contain a prompt subject? ==="
if grep -q "KeychainPromptAclSubject" "$LOG"; then
  echo "YES - at least one key offers an interactive prompt fallback:"
  grep -o "ObjectAcl REJECTS access using ACL:.*" "$LOG" | grep -o "KeychainPromptAclSubject[^]]*\]" | sort -u | sed 's/^/  /'
else
  echo "NO - no prompt subject was present in any evaluated ACL"
fi
echo
echo "=== per-key detail ==="
grep -o "ObjectAcl REJECTS access using ACL:.*" "$LOG" | sed 's/ObjectAcl REJECTS access using ACL: //' | sort -u | while IFS= read -r l; do
  # case, not grep: a substring test through a pipe can fail under pipefail if grep
  # exits early and the writer takes SIGPIPE.
  case "$l" in
    *KeychainPromptAclSubject*) echo "PROMPT FALLBACK: $l";;
    *)                          echo "HARD ONLY:       $l";;
  esac
done
