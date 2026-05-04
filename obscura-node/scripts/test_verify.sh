#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# Tonkl Node - Proof Verification End-to-End Test
#
# Tests the full flow:
#   1. Generate VKs for all circuits (if missing)
#   2. Set up VK directory structure
#   3. Start the node with --vk-dir
#   4. Submit a valid mint transaction → should be accepted
#   5. Submit a garbage proof → should be rejected
#   6. Shut down and report results
#
# Prerequisites:
#   - bb (Barretenberg) in PATH
#   - nargo in PATH (for compile if needed)
#   - obscura-node built (cargo build --release)
#
# Usage:
#   cd ~/Desktop/obscura/obscura-node
#   bash scripts/test_verify.sh
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NODE_BIN="$ROOT/obscura-node/target/release/obscura-node"
VK_DIR="$ROOT/obscura-node/test-vks"
DATA_DIR="/tmp/obscura-test-$$"
PORT=9199
PASS=0
FAIL=0

cleanup() {
    # Kill node if running
    if [[ -n "${NODE_PID:-}" ]]; then
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR"
    rm -rf "$VK_DIR"
}
trap cleanup EXIT

echo "═══════════════════════════════════════════════════════════════"
echo "  Tonkl Node - Proof Verification E2E Test"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────────────────────────────
# Step 1: Ensure VKs exist for all circuits
# ─────────────────────────────────────────────────────────────────────
echo "[1/6] Checking verification keys..."

for circuit in obscura-transfer obscura-merge obscura-split obscura-mint; do
    CIRCUIT_DIR="$ROOT/$circuit"
    # VK can be at target/vk/vk (bb write_vk -o dir) or target/vk (bb prove -k file)
    VK_FILE=""
    if [[ -f "$CIRCUIT_DIR/target/vk/vk" ]]; then
        VK_FILE="$CIRCUIT_DIR/target/vk/vk"
    elif [[ -f "$CIRCUIT_DIR/target/vk" ]]; then
        VK_FILE="$CIRCUIT_DIR/target/vk"
    fi

    if [[ -n "$VK_FILE" ]]; then
        echo "  ✓ $circuit VK exists ($(wc -c < "$VK_FILE") bytes) at $VK_FILE"
    else
        echo "  → Generating VK for $circuit..."
        CIRCUIT_JSON="$CIRCUIT_DIR/target/${circuit##obscura-}.json"
        if [[ ! -f "$CIRCUIT_JSON" ]]; then
            CIRCUIT_JSON=$(ls "$CIRCUIT_DIR"/target/*.json 2>/dev/null | head -1 || true)
        fi
        if [[ -z "$CIRCUIT_JSON" || ! -f "$CIRCUIT_JSON" ]]; then
            echo "  → Compiling $circuit..."
            (cd "$CIRCUIT_DIR" && nargo compile 2>&1 | tail -1)
            CIRCUIT_JSON=$(ls "$CIRCUIT_DIR"/target/*.json 2>/dev/null | head -1)
        fi
        # Write VK as a single file (not inside a subdir)
        bb write_vk -b "$CIRCUIT_JSON" -o "$CIRCUIT_DIR/target/vk_dir"
        VK_FILE="$CIRCUIT_DIR/target/vk_dir/vk"
        echo "  ✓ $circuit VK generated at $VK_FILE"
    fi
done

# ─────────────────────────────────────────────────────────────────────
# Step 2: Set up VK directory for the node
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[2/6] Setting up VK directory..."
mkdir -p "$VK_DIR"/{transfer,merge,split,mint}

# Helper: find VK file for a circuit (handles both layouts)
find_vk() {
    local dir="$ROOT/$1/target"
    if [[ -f "$dir/vk/vk" ]]; then echo "$dir/vk/vk"
    elif [[ -f "$dir/vk" ]]; then echo "$dir/vk"
    elif [[ -f "$dir/vk_dir/vk" ]]; then echo "$dir/vk_dir/vk"
    fi
}

cp "$(find_vk obscura-transfer)" "$VK_DIR/transfer/vk"
cp "$(find_vk obscura-merge)" "$VK_DIR/merge/vk"
cp "$(find_vk obscura-split)" "$VK_DIR/split/vk"
cp "$(find_vk obscura-mint)" "$VK_DIR/mint/vk"
echo "  ✓ VK directory ready at $VK_DIR"

# ─────────────────────────────────────────────────────────────────────
# Step 3: Start the node
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[3/6] Starting node with proof verification..."
"$NODE_BIN" run \
    --port "$PORT" \
    --data-dir "$DATA_DIR" \
    --vk-dir "$VK_DIR" \
    2>&1 | sed 's/^/  [node] /' &
NODE_PID=$!

# Wait for node to be ready
sleep 2
if ! kill -0 "$NODE_PID" 2>/dev/null; then
    echo "  ✗ Node failed to start!"
    exit 1
fi

# Check status
STATUS=$(curl -s -X POST http://127.0.0.1:$PORT \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"get_status","params":[],"id":1}')
echo "  ✓ Node running: $STATUS"

# ─────────────────────────────────────────────────────────────────────
# Step 4: Submit a valid mint transaction (real proof)
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[4/6] Submitting valid mint transaction..."

# Read the real proof and public inputs as hex
PROOF_HEX="0x$(xxd -p -c0 "$ROOT/obscura-mint/target/proof/proof")"
PI_HEX="0x$(xxd -p -c0 "$ROOT/obscura-mint/target/proof/public_inputs")"

# The mint circuit has 36 public inputs (32 commitments + total_minted + asset_id + authority_pk_x + authority_pk_y)
# Each is a 32-byte field element in the public_inputs binary
PI_COUNT=$(($(wc -c < "$ROOT/obscura-mint/target/proof/public_inputs") / 32))
echo "  Public inputs: $PI_COUNT fields"

# Build public_inputs array (each 32-byte chunk as hex)
PI_ARRAY="["
for i in $(seq 0 $((PI_COUNT - 1))); do
    OFFSET=$((i * 32))
    CHUNK="0x$(xxd -p -l 32 -s $OFFSET "$ROOT/obscura-mint/target/proof/public_inputs" | tr -d '\n')"
    if [[ $i -gt 0 ]]; then PI_ARRAY+=","; fi
    PI_ARRAY+="\"$CHUNK\""
done
PI_ARRAY+="]"

# The first 32 public inputs are the commitments (cm_outs)
# Extract them for new_commitments field
CM_ARRAY="["
for i in $(seq 0 31); do
    OFFSET=$((i * 32))
    CHUNK="0x$(xxd -p -l 32 -s $OFFSET "$ROOT/obscura-mint/target/proof/public_inputs" | tr -d '\n')"
    if [[ $i -gt 0 ]]; then CM_ARRAY+=","; fi
    CM_ARRAY+="\"$CHUNK\""
done
CM_ARRAY+="]"

# Build the submit_tx request
REQUEST=$(cat <<ENDJSON
{
    "jsonrpc": "2.0",
    "method": "submit_tx",
    "params": [{
        "tx_type": "mint",
        "proof": "$PROOF_HEX",
        "public_inputs": $PI_ARRAY,
        "new_commitments": $CM_ARRAY,
        "nullifiers": [],
        "merkle_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "fee": 0,
        "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000001"
    }],
    "id": 2
}
ENDJSON
)

RESULT=$(curl -s -X POST http://127.0.0.1:$PORT \
    -H "Content-Type: application/json" \
    -d "$REQUEST")

echo "  Response: $RESULT"

if echo "$RESULT" | grep -q '"accepted":true'; then
    echo "  ✓ PASS: Valid mint transaction accepted"
    PASS=$((PASS + 1))
else
    echo "  ✗ FAIL: Valid mint transaction was rejected"
    FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────────────────────────
# Step 5: Submit a garbage proof (should be rejected)
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[5/6] Submitting garbage proof (should be rejected)..."

# Use the same public inputs but with random proof bytes
GARBAGE_PROOF="0x$(head -c 16256 /dev/urandom | xxd -p -c0)"

REQUEST_BAD=$(cat <<ENDJSON
{
    "jsonrpc": "2.0",
    "method": "submit_tx",
    "params": [{
        "tx_type": "mint",
        "proof": "$GARBAGE_PROOF",
        "public_inputs": $PI_ARRAY,
        "new_commitments": $CM_ARRAY,
        "nullifiers": [],
        "merkle_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "fee": 0,
        "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000001"
    }],
    "id": 3
}
ENDJSON
)

RESULT_BAD=$(curl -s -X POST http://127.0.0.1:$PORT \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BAD")

echo "  Response: $(echo "$RESULT_BAD" | head -c 200)"

if echo "$RESULT_BAD" | grep -q '"error"'; then
    echo "  ✓ PASS: Garbage proof correctly rejected"
    PASS=$((PASS + 1))
else
    echo "  ✗ FAIL: Garbage proof was accepted (should have been rejected)"
    FAIL=$((FAIL + 1))
fi

# ─────────────────────────────────────────────────────────────────────
# Step 6: Produce a block and check status
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[6/6] Producing block..."

BLOCK_RESULT=$(curl -s -X POST http://127.0.0.1:$PORT \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"produce_block","params":[],"id":4}')

echo "  Block: $BLOCK_RESULT"

FINAL_STATUS=$(curl -s -X POST http://127.0.0.1:$PORT \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"get_status","params":[],"id":5}')

echo "  Final status: $FINAL_STATUS"

# ─────────────────────────────────────────────────────────────────────
# Results
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
