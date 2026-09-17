#!/bin/bash
# Build the POC tools. Deprecated Security APIs are intentional here: item ACLs
# are only reachable through the legacy file-keychain API surface.
set -euo pipefail
cd "$(dirname "$0")"

build() { # $1=src  $2=out
  echo "building $2"
  clang -fobjc-arc -O1 -Wall -Wno-deprecated-declarations \
    -framework Foundation -framework Security \
    -o "bin/$2" "tools/$1"
}
mkdir -p bin
build pocsetup.m  pocsetup
build pocclient.m pocclient
build pocse.m     pocse
build pocexport.m pocexport
build rmkeys.m    rmkeys
echo "ok"
