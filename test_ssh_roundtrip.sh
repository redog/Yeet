#!/bin/bash
# test_ssh_roundtrip.sh
# Tests that yeet.ps1 upload+get preserves SSH key content exactly.
# Verifies no extra line feeds or CR characters are introduced.
#
# Usage: ./test_ssh_roundtrip.sh
# Requires: pwsh, bw (logged in & unlocked), ssh-keygen, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
YEET_PS1="$SCRIPT_DIR/Yeet.ps1"
TEMP_DIR=$(mktemp -d)
SSH_DIR="$HOME/.ssh"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
TEST_KEY_NAME="yeet-test-$TIMESTAMP"

PASS=true

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "    ${GREEN}PASS${NC}: $*"; }
fail() { echo -e "    ${RED}FAIL${NC}: $*"; PASS=false; }
warn() { echo -e "    ${YELLOW}WARN${NC}: $*"; }
step() { echo -e "\n[${1}] ${2}"; }

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    echo "=== Cleanup ==="

    # Local temp files
    rm -rf "$TEMP_DIR"

    # Retrieved private key written by Yeet.ps1 get
    rm -f "$SSH_DIR/$TEST_KEY_NAME"

    # Bitwarden entry
    if command -v bw &>/dev/null && bw status 2>/dev/null | grep -q '"status":"unlocked"'; then
        ITEM_ID=$(bw list items 2>/dev/null \
            | jq -r --arg n "$TEST_KEY_NAME" \
                '.[] | select(.type == 5 and .name == $n) | .id' 2>/dev/null || true)
        if [ -n "$ITEM_ID" ]; then
            bw delete item "$ITEM_ID" >/dev/null 2>&1 \
                && echo "  Removed '$TEST_KEY_NAME' from Bitwarden." \
                || warn "Could not remove '$TEST_KEY_NAME' from Bitwarden (id=$ITEM_ID). Remove manually."
        fi
    fi
}
trap cleanup EXIT

# ── prerequisites ─────────────────────────────────────────────────────────────
echo "=== Yeet.ps1 SSH Key Roundtrip Test ==="
echo "    Key name : $TEST_KEY_NAME"
echo "    Temp dir : $TEMP_DIR"

for cmd in pwsh bw ssh-keygen jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' not found in PATH. Aborting."
        exit 1
    fi
done

if ! bw status 2>/dev/null | grep -q '"status":"unlocked"'; then
    echo "Error: Bitwarden is not logged in / vault is locked. Run 'bw login' or 'bw unlock'."
    exit 1
fi

# ── step 1: generate a fresh ed25519 key pair ─────────────────────────────────
step 1 "Generating test ed25519 key pair..."
ssh-keygen -t ed25519 -f "$TEMP_DIR/$TEST_KEY_NAME" -N "" -C "$TEST_KEY_NAME" -q

ORIG_PRIV="$TEMP_DIR/$TEST_KEY_NAME"
ORIG_PUB="$TEMP_DIR/$TEST_KEY_NAME.pub"

ORIG_PRIV_BYTES=$(wc -c < "$ORIG_PRIV")
ORIG_PUB_BYTES=$(wc -c  < "$ORIG_PUB")
ORIG_PRIV_SHA=$(sha256sum "$ORIG_PRIV" | awk '{print $1}')
ORIG_PUB_SHA=$(sha256sum "$ORIG_PUB"  | awk '{print $1}')

echo "    Private : $ORIG_PRIV_BYTES bytes  sha256=$ORIG_PRIV_SHA"
echo "    Public  : $ORIG_PUB_BYTES bytes  sha256=$ORIG_PUB_SHA"

# ── step 2: upload via Yeet.ps1 ───────────────────────────────────────────────
step 2 "Uploading to Bitwarden via Yeet.ps1 upload..."
pwsh "$YEET_PS1" upload "$ORIG_PRIV" "$TEST_KEY_NAME"
echo "    Upload complete."

# ── step 3: fetch back via Yeet.ps1 (answer 'n' to authorized_keys prompt) ────
step 3 "Downloading from Bitwarden via Yeet.ps1 get..."
# Read-Host in pwsh reads from stdin when piped
echo "n" | pwsh "$YEET_PS1" get "$TEST_KEY_NAME"

RETRIEVED="$SSH_DIR/$TEST_KEY_NAME"
if [ ! -f "$RETRIEVED" ]; then
    echo "Error: Retrieved key not found at '$RETRIEVED'. Aborting."
    exit 1
fi
echo "    Download complete → $RETRIEVED"

# ── step 4: compare ───────────────────────────────────────────────────────────
step 4 "Comparing original vs retrieved private key..."

RETR_BYTES=$(wc -c < "$RETRIEVED")
RETR_SHA=$(sha256sum "$RETRIEVED" | awk '{print $1}')
echo "    Original  : $ORIG_PRIV_BYTES bytes  sha256=$ORIG_PRIV_SHA"
echo "    Retrieved : $RETR_BYTES bytes  sha256=$RETR_SHA"

# The upload command normalises to: (content stripped of \r, trimmed) + \n
# So compute what the normalised original should look like.
NORMALISED="$TEMP_DIR/${TEST_KEY_NAME}.normalised"
perl -pe 's/\r//g; END { s/\s+\z/\n/ }' "$ORIG_PRIV" > "$NORMALISED"
NORM_BYTES=$(wc -c < "$NORMALISED")
NORM_SHA=$(sha256sum "$NORMALISED" | awk '{print $1}')
echo "    Normalised: $NORM_BYTES bytes  sha256=$NORM_SHA  (expected after upload normalisation)"

# Primary check: retrieved == normalised original
if [ "$RETR_SHA" = "$NORM_SHA" ]; then
    ok "Retrieved key matches normalised original exactly."
else
    fail "Retrieved key does NOT match normalised original."
fi

# Extra: no \r in retrieved file
if ! grep -qP '\r' "$RETRIEVED" 2>/dev/null; then
    ok "No carriage-return (\\\\r) characters in retrieved key."
else
    fail "Retrieved key contains carriage-return (\\\\r) characters."
fi

# Extra: exactly one trailing newline
TRAILING_NEWLINES=$(tail -c 10 "$RETRIEVED" | od -An -tx1 | tr ' ' '\n' | grep -c '^0a$' || true)
if [ "$TRAILING_NEWLINES" -eq 1 ]; then
    ok "Retrieved key ends with exactly one newline."
else
    fail "Retrieved key has $TRAILING_NEWLINES trailing newline byte(s) (expected 1)."
fi

# Extra: ssh-keygen can parse the retrieved key (it's not corrupted)
FINGERPRINT=$(ssh-keygen -lf "$RETRIEVED" 2>&1)
if [ $? -eq 0 ]; then
    ok "Retrieved private key is valid: $FINGERPRINT"
else
    fail "ssh-keygen cannot parse retrieved key: $FINGERPRINT"
fi

# Diff for visibility when there IS a difference
if [ "$RETR_SHA" != "$NORM_SHA" ]; then
    echo ""
    echo "    --- last 8 bytes of normalised original (hex) ---"
    xxd "$NORMALISED" | tail -3
    echo "    --- last 8 bytes of retrieved key (hex) ---"
    xxd "$RETRIEVED"  | tail -3
fi

# ── result ────────────────────────────────────────────────────────────────────
echo ""
if [ "$PASS" = "true" ]; then
    echo -e "${GREEN}=== ALL CHECKS PASSED ===${NC}"
    exit 0
else
    echo -e "${RED}=== ONE OR MORE CHECKS FAILED ===${NC}"
    exit 1
fi
