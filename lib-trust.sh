#!/bin/bash
# Shared helpers for the POC. Sourced, not executed.

# ---------------------------------------------------------------------------
# Trust settings
#
# Trust settings are keyed to the certificate's SHA-1, and `security
# remove-trusted-cert` needs the certificate itself to match. Once make-pki.sh has
# regenerated a CA, or the certificate has been deleted from a keychain, that command
# silently leaves the old setting behind.
#
# IMPORTANT, and measured: ANY change to the trust store raises an authorization dialog
# ("You are making changes to your Certificate Trust Settings") that demands Touch ID or
# the login password. This includes a first-time `add-trusted-cert`, which an earlier
# revision of this file wrongly assumed did not prompt. `trust-settings-import` is silent
# only when the imported list is identical to the current one.
#
# Consequence: nothing in this repository may modify trust settings unattended. Every
# function here that would do so refuses unless POC_ALLOW_TRUST_CHANGE=1 is set, so a
# script can never block on a GUI dialog.
# ---------------------------------------------------------------------------

POC_CA_NAMES=("POC Private Root CA 1" "POC Rogue Root CA 2" "POC Enterprise Root")

# Print the names of certificates that currently have user trust settings.
poc_trust_list() {
    security dump-trust-settings 2>/dev/null | sed -n 's/^Cert [0-9]*: //p' || true
}

# Guard for any trust-store write. Returns non-zero (and explains) unless explicitly
# permitted, so an unattended run fails fast instead of hanging on a dialog.
poc_trust_write_guard() {
    if [ "${POC_ALLOW_TRUST_CHANGE:-0}" = "1" ]; then
        return 0
    fi
    cat >&2 <<'EOF'
  REFUSING to modify trust settings: this operation raises a Touch ID / password dialog
  and would block an unattended run.

  Trust settings must be established once, interactively. To do that, re-run with:

      POC_ALLOW_TRUST_CHANGE=1 ./setup-trust.sh

  The dialog will name "Certificate Trust Settings"; approve it once. After that, do not
  re-run make-pki.sh, because regenerating a CA invalidates the trust and you will be
  prompted again.
EOF
    return 1
}

# Add a trust setting for a certificate, interactively only. Dispatches through the
# Python helper so the write is a single import (see tools/set-trust.py).
poc_trust_add() {
    local ca="$1"
    poc_trust_write_guard || return 1
    python3 "$POC_ROOT/tools/set-trust.py" add "$ca" || return 1
}

# Remove this POC's entries from the user trust list, interactively only.
poc_trust_drop() {
    poc_trust_write_guard || return 1
    printf '%s\n' "${POC_CA_NAMES[@]}" | while IFS= read -r n; do printf '%s\n' "$n"; done >/dev/null
    python3 "$POC_ROOT/tools/set-trust.py" drop "${POC_CA_NAMES[@]}"
}

# ---------------------------------------------------------------------------
# Keychain search list
# ---------------------------------------------------------------------------

poc_keychain_list() {
    security list-keychains -d user 2>/dev/null | sed -n 's/^ *"\(.*\)"$/\1/p' || true
}

# Add a keychain to the user search list, preserving what is already there.
#
# `codesign --keychain <path>` is not sufficient on its own: if the keychain is absent from
# the search list, codesign reports "no identity found" even with an explicit --keychain.
# Replacing the list outright breaks any other POC flow that later needs a different
# keychain, so this is additive.
poc_keychain_add() {
    local kc="$1" p
    local -a list=()
    while IFS= read -r p; do
        [ -n "$p" ] && list+=("$p")
    done < <(poc_keychain_list)
    for p in "${list[@]}"; do
        [ "$p" = "$kc" ] && return 0
    done
    list+=("$kc")
    security list-keychains -d user -s "${list[@]}"
}

poc_keychain_ensure_login() {
    poc_keychain_add "$HOME/Library/Keychains/login.keychain-db"
}