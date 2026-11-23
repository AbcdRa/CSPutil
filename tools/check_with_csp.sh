#!/usr/bin/env bash
# Verify that a CryptoPro container directory is accepted by the installed CSP.
#
# Usage:
#   tools/check_with_csp.sh ./container [pin]
#
# The container is copied into the current user's CSP key store under a
# temporary 8-character name, checked with csptest, and removed afterwards.
# This is an optional integration check; the regular unit tests do not touch
# the CSP key store.

set -euo pipefail

CONTAINER=${1:?usage: check_with_csp.sh CONTAINER_DIR [PIN]}
PIN=${2-}
CSP=${CSPTEST:-/opt/cprocsp/bin/amd64/csptest}
KEYDIR=${CSP_KEYDIR:-/var/opt/cprocsp/keys/${USER}}

if [[ ! -x "$CSP" ]]; then
    echo "csptest not found: $CSP" >&2
    exit 2
fi
if [[ ! -d "$KEYDIR" ]]; then
    echo "CSP key store not found: $KEYDIR" >&2
    exit 2
fi
if [[ ! -f "$CONTAINER/name.key" ]]; then
    echo "not a CryptoPro container: $CONTAINER" >&2
    exit 2
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=$(python3 - "$CONTAINER/name.key" "$ROOT" <<'PY'
import sys
sys.path.insert(0, sys.argv[2])
from pathlib import Path
from cspcombine_lib.der import der_read

root, _ = der_read(Path(sys.argv[1]).read_bytes())
if root.children and root.children[0].tag in (0x16, 0x0C):
    print(root.children[0].value.decode("utf-8", "replace"))
else:
    raise SystemExit("cannot read container name")
PY
)

# CSP expects a short file-system name.  The real name is taken from name.key.
TEMPNAME=$(printf 'zz%06x' "$$")
TARGET="$KEYDIR/$TEMPNAME.000"

cleanup() {
    rm -rf "$TARGET"
}
trap cleanup EXIT

rm -rf "$TARGET"
cp -a "$CONTAINER" "$TARGET"
chmod 700 "$TARGET"
chmod 600 "$TARGET"/*

if [[ -n "$PIN" ]]; then
    AUTH=(-password "$PIN")
else
    AUTH=(-nullpasswd)
fi

set +e
"$CSP" -keyset -check=15 -container "$NAME" "${AUTH[@]}" -silent
RC=$?
set -e
echo "container name: $NAME"
echo "exit code: $RC"
exit "$RC"
