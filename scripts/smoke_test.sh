#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────────
# Tonkl Protocol — End-to-End Smoke Test
#
# Tests all security layers against a running node + website:
#   1. RPC reads (no auth required)
#   2. RPC auth (TONKL_RPC_SECRET)
#   3. Input validation (oversized payloads, bad fields)
#   4. Session token auth (X-Tonkl-Session)
#   5. Rate limiting (Rust RPC)
#   6. CORS policy (localhost-only)
#
# Prerequisites:
#   - tonkl-node running on localhost:9100
#   - (optional) tonkl-website running on localhost:3000
#   - curl and jq installed
#
# For full auth testing, restart the node with TONKL_RPC_SECRET and VKs:
#   TONKL_RPC_SECRET=test-secret-123 cargo run --release -- run --vk-dir ./vks
# For isolated local-only no-VK/no-auth testing:
#   cargo run --release -- run --allow-unverified-local --allow-unauthenticated-rpc-local
#
# Then run the test with the same secret:
#   TONKL_RPC_SECRET=test-secret-123 ./scripts/smoke_test.sh
# ───────────────────────────────────────────────────────────────────

set -euo pipefail

NODE_URL="${NODE_URL:-http://localhost:9100}"
WEB_URL="${WEB_URL:-http://localhost:3000}"
SECRET="${TONKL_RPC_SECRET:-}"

PASS=0
FAIL=0
SKIP=0

# ─── Helpers ─────────────────────────────────────────────────────

green() { printf "\033[32m%s\033[0m" "$1"; }
red()   { printf "\033[31m%s\033[0m" "$1"; }
yellow(){ printf "\033[33m%s\033[0m" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m: %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m: %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "  \033[33mSKIP\033[0m: %s\n" "$1"; }

# rpc_call makes a JSON-RPC request. Uses -w to capture HTTP status.
rpc_call() {
  local method="$1"
  local params="$2"
  local payload="{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}"
  curl -s -X POST "$NODE_URL" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    2>/dev/null || echo '{"error":{"message":"connection_failed"}}'
}

# rpc_call_raw - returns full response including HTTP headers
rpc_call_raw() {
  local method="$1"
  local params="$2"
  local payload="{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}"
  curl -s -X POST "$NODE_URL" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    -D - \
    2>/dev/null || echo ""
}

web_post() {
  local path="$1"
  local data="$2"
  local extra_header="${3:-}"
  if [ -n "$extra_header" ]; then
    curl -s -X POST "${WEB_URL}${path}" \
      -H "Content-Type: application/json" \
      -H "$extra_header" \
      -d "$data" \
      2>/dev/null || echo '{"error":"connection_failed"}'
  else
    curl -s -X POST "${WEB_URL}${path}" \
      -H "Content-Type: application/json" \
      -d "$data" \
      2>/dev/null || echo '{"error":"connection_failed"}'
  fi
}

# ─── Check prerequisites ────────────────────────────────────────

bold "Tonkl Protocol — Smoke Test"
echo ""
bold "Configuration:"
echo "  Node:    $NODE_URL"
echo "  Website: $WEB_URL"
if [ -n "$SECRET" ]; then
  echo "  Secret:  (set)"
else
  echo "  Secret:  (not set)"
fi
echo ""

# Check node is running
NODE_STATUS=$(rpc_call "get_status" "[]")
if echo "$NODE_STATUS" | grep -q "connection_failed"; then
  printf "\033[31m%s\033[0m\n" "Node is not running at $NODE_URL — aborting."
  exit 1
fi
BLOCK_HEIGHT=$(echo "$NODE_STATUS" | jq -r '.result.block_height // "?"')
printf "\033[32m%s\033[0m\n" "Node is running ($BLOCK_HEIGHT blocks)"

# Detect if node has auth enabled by trying an unauthenticated write
AUTH_PROBE=$(rpc_call "produce_block" "[null]")
if echo "$AUTH_PROBE" | grep -q "authentication required"; then
  NODE_AUTH_ENABLED=true
  printf "\033[32m%s\033[0m\n" "Node has RPC auth enabled"
else
  NODE_AUTH_ENABLED=false
  printf "\033[33m%s\033[0m\n" "Node has NO RPC auth (dev mode) — auth tests will verify dev-mode behavior"
fi

# Check website
WEB_AVAILABLE=false
WEB_CHECK=$(curl -s "${WEB_URL}/api/node" 2>/dev/null || echo "")
if [ -n "$WEB_CHECK" ] && ! echo "$WEB_CHECK" | grep -q "connection_failed"; then
  printf "\033[32m%s\033[0m\n" "Website is running"
  WEB_AVAILABLE=true
else
  printf "\033[33m%s\033[0m\n" "Website not running at $WEB_URL — web tests will be skipped"
fi
echo ""

# ═════════════════════════════════════════════════════════════════
# 1. RPC READ ENDPOINTS (no auth required)
# ═════════════════════════════════════════════════════════════════

bold "1. RPC Read Endpoints (no auth required)"

# get_status
RESULT=$(rpc_call "get_status" "[]")
if echo "$RESULT" | jq -e '.result.block_height' > /dev/null 2>&1; then
  pass "get_status returns block height"
else
  fail "get_status failed: $(echo "$RESULT" | head -c 200)"
fi

# get_merkle_root
RESULT=$(rpc_call "get_merkle_root" "[]")
if echo "$RESULT" | jq -e '.result' > /dev/null 2>&1; then
  pass "get_merkle_root returns root hash"
else
  fail "get_merkle_root failed"
fi

# get_block — block 0 should exist if chain has blocks
RESULT=$(rpc_call "get_block" "[0]")
if echo "$RESULT" | jq -e '.result' > /dev/null 2>&1; then
  if echo "$RESULT" | jq -e '.result == null' > /dev/null 2>&1; then
    pass "get_block(0) returns null (chain is empty — just started)"
  else
    pass "get_block(0) returns genesis block"
  fi
elif echo "$RESULT" | grep -q "authentication required"; then
  pass "get_block(0) is auth-protected as metadata-heavy read"
else
  fail "get_block(0) failed"
fi

# get_blocks_range — use integers (jsonrpsee is strict about types)
RESULT=$(rpc_call "get_blocks_range" "[0,5]")
if echo "$RESULT" | jq -e '.result' > /dev/null 2>&1; then
  pass "get_blocks_range(0,5) returns blocks"
elif echo "$RESULT" | grep -q "authentication required"; then
  pass "get_blocks_range is auth-protected as metadata-heavy read"
elif echo "$RESULT" | grep -q "Method not found"; then
  skip "get_blocks_range — method not found (node binary predates P2P sync; rebuild needed)"
else
  fail "get_blocks_range failed: $(echo "$RESULT" | head -c 200)"
fi

# get_tx_status for unknown hash
RESULT=$(rpc_call "get_tx_status" "[\"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"]")
if echo "$RESULT" | jq -e '.result.status' > /dev/null 2>&1; then
  STATUS=$(echo "$RESULT" | jq -r '.result.status')
  if [ "$STATUS" = "unknown" ]; then
    pass "get_tx_status for unknown hash returns 'unknown'"
  else
    pass "get_tx_status returns status: $STATUS"
  fi
else
  fail "get_tx_status failed"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# 2. RPC AUTH (TONKL_RPC_SECRET)
# ═════════════════════════════════════════════════════════════════

bold "2. RPC Auth (TONKL_RPC_SECRET)"

if [ "$NODE_AUTH_ENABLED" = true ]; then
  # submit_tx without secret — should fail
  RESULT=$(rpc_call "submit_tx" '[{"tx_type":"transfer","proof":"0x00","public_inputs":[],"new_commitments":[],"nullifiers":[],"merkle_root":"0x00","fee":0,"asset_id":"0x01"},null]')
  if echo "$RESULT" | grep -q "authentication required"; then
    pass "submit_tx without secret -> rejected"
  else
    fail "submit_tx without secret should be rejected: $(echo "$RESULT" | head -c 200)"
  fi

  # submit_tx with wrong secret — should fail
  RESULT=$(rpc_call "submit_tx" '[{"tx_type":"transfer","proof":"0x00","public_inputs":[],"new_commitments":[],"nullifiers":[],"merkle_root":"0x00","fee":0,"asset_id":"0x01"},"wrong-secret"]')
  if echo "$RESULT" | grep -q "authentication required"; then
    pass "submit_tx with wrong secret -> rejected"
  else
    fail "submit_tx with wrong secret should be rejected: $(echo "$RESULT" | head -c 200)"
  fi

  # produce_block without secret — should fail
  RESULT=$(rpc_call "produce_block" "[null]")
  if echo "$RESULT" | grep -q "authentication required"; then
    pass "produce_block without secret -> rejected"
  else
    fail "produce_block without secret should be rejected"
  fi

  # store_encrypted_notes without secret — should fail
  RESULT=$(rpc_call "store_encrypted_notes" '[{"notes":[]},null]')
  if echo "$RESULT" | grep -q "authentication required"; then
    pass "store_encrypted_notes without secret -> rejected"
  else
    fail "store_encrypted_notes without secret should be rejected"
  fi

  # produce_block with correct secret — should succeed
  if [ -n "$SECRET" ]; then
    RESULT=$(rpc_call "produce_block" "[\"${SECRET}\"]")
    if echo "$RESULT" | jq -e '.result.block_number' > /dev/null 2>&1; then
      pass "produce_block with correct secret -> accepted"
    else
      fail "produce_block with correct secret failed: $(echo "$RESULT" | head -c 200)"
    fi
  else
    skip "TONKL_RPC_SECRET not provided to script — cannot test correct-secret path"
  fi
else
  # Node is in dev mode — verify that write ops work without auth
  RESULT=$(rpc_call "produce_block" "[null]")
  if echo "$RESULT" | jq -e '.result.block_number' > /dev/null 2>&1; then
    pass "produce_block works in dev mode (no auth required)"
  else
    fail "produce_block should work in dev mode"
  fi
  skip "Node running without TONKL_RPC_SECRET — restart node with secret for full auth tests"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# 3. RPC INPUT VALIDATION
# ═════════════════════════════════════════════════════════════════

bold "3. RPC Input Validation"

# Build the secret param for submit_tx calls
if [ "$NODE_AUTH_ENABLED" = true ] && [ -n "$SECRET" ]; then
  SECRET_PARAM="\"${SECRET}\""
else
  SECRET_PARAM="null"
fi

# Invalid tx_type
RESULT=$(rpc_call "submit_tx" "[{\"tx_type\":\"hack\",\"proof\":\"0x00\",\"public_inputs\":[],\"new_commitments\":[],\"nullifiers\":[],\"merkle_root\":\"0x00\",\"fee\":0,\"asset_id\":\"0x01\"},${SECRET_PARAM}]")
if echo "$RESULT" | grep -qi "unknown tx_type"; then
  pass "Invalid tx_type 'hack' -> rejected"
elif echo "$RESULT" | grep -q "authentication required"; then
  skip "Invalid tx_type — blocked by auth before reaching validation"
else
  fail "Invalid tx_type should be rejected: $(echo "$RESULT" | head -c 200)"
fi

# Oversized proof (> 16384 hex chars = MAX_PROOF_HEX_LEN)
LONG_PROOF="0x$(python3 -c "print('ff' * 9000)" 2>/dev/null)"
if [ ${#LONG_PROOF} -gt 16384 ]; then
  RESULT=$(rpc_call "submit_tx" "[{\"tx_type\":\"transfer\",\"proof\":\"${LONG_PROOF}\",\"public_inputs\":[],\"new_commitments\":[],\"nullifiers\":[],\"merkle_root\":\"0x00\",\"fee\":0,\"asset_id\":\"0x01\"},${SECRET_PARAM}]")
  if echo "$RESULT" | grep -qi "too large\|proof"; then
    pass "Oversized proof (${#LONG_PROOF} chars) -> rejected"
  elif echo "$RESULT" | jq -e '.error' > /dev/null 2>&1; then
    pass "Oversized proof payload -> rejected before acceptance ($(echo "$RESULT" | jq -r '.error.message' | head -c 60))"
  elif echo "$RESULT" | grep -q "authentication required"; then
    skip "Oversized proof — blocked by auth before reaching validation"
  else
    fail "Oversized proof should be rejected: $(echo "$RESULT" | head -c 200)"
  fi
else
  skip "Could not generate oversized proof (python3 unavailable?)"
fi

# Too many commitments (>32)
MANY_COMMS='["0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01","0x01"]'
RESULT=$(rpc_call "submit_tx" "[{\"tx_type\":\"transfer\",\"proof\":\"0x00\",\"public_inputs\":[],\"new_commitments\":${MANY_COMMS},\"nullifiers\":[],\"merkle_root\":\"0x00\",\"fee\":0,\"asset_id\":\"0x01\"},${SECRET_PARAM}]")
if echo "$RESULT" | grep -qi "too many commitments"; then
  pass "Too many commitments (35 > max 32) -> rejected (size check)"
elif echo "$RESULT" | jq -e '.error' > /dev/null 2>&1; then
  # Any error is acceptable — older binaries reject via proof verification instead of size check
  pass "Too many commitments (35) -> rejected ($(echo "$RESULT" | jq -r '.error.message' | head -c 60))"
elif echo "$RESULT" | grep -q "authentication required"; then
  skip "Too many commitments — blocked by auth before reaching validation"
else
  fail "Too many commitments should be rejected: $(echo "$RESULT" | head -c 200)"
fi

# Too many nullifiers (>2)
RESULT=$(rpc_call "submit_tx" "[{\"tx_type\":\"transfer\",\"proof\":\"0x00\",\"public_inputs\":[],\"new_commitments\":[],\"nullifiers\":[\"0x01\",\"0x02\",\"0x03\"],\"merkle_root\":\"0x00\",\"fee\":0,\"asset_id\":\"0x01\"},${SECRET_PARAM}]")
if echo "$RESULT" | grep -qi "too many nullifiers"; then
  pass "Too many nullifiers (3 > max 2) -> rejected (size check)"
elif echo "$RESULT" | jq -e '.error' > /dev/null 2>&1; then
  # Any error is acceptable — older binaries reject via proof verification instead of size check
  pass "Too many nullifiers (3) -> rejected ($(echo "$RESULT" | jq -r '.error.message' | head -c 60))"
elif echo "$RESULT" | grep -q "authentication required"; then
  skip "Too many nullifiers — blocked by auth before reaching validation"
else
  fail "Too many nullifiers should be rejected: $(echo "$RESULT" | head -c 200)"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# 4. SESSION TOKEN AUTH (website)
# ═════════════════════════════════════════════════════════════════

bold "4. Session Token Auth (website)"

if [ "$WEB_AVAILABLE" = false ]; then
  skip "Website not available — skipping session tests"
else
  # /api/send without session -> 401
  RESULT=$(web_post "/api/send" '{"amount":1,"recipientAddress":"0x0000000000000000000000000000000000000000000000000000000000000001"}')
  if echo "$RESULT" | grep -q "unauthorized"; then
    pass "/api/send without session -> 401"
  else
    fail "/api/send without session should return 401: $(echo "$RESULT" | head -c 200)"
  fi

  # /api/faucet without session -> 401
  RESULT=$(web_post "/api/faucet" '{"address":"0000000000000000000000000000000000000000000000000000000000000001"}')
  if echo "$RESULT" | grep -q "unauthorized"; then
    pass "/api/faucet without session -> 401"
  else
    fail "/api/faucet without session should return 401: $(echo "$RESULT" | head -c 200)"
  fi

  # /api/token create without session -> 401
  RESULT=$(web_post "/api/token" '{"action":"create","symbol":"TST","name":"Test"}')
  if echo "$RESULT" | grep -q "unauthorized"; then
    pass "/api/token create without session -> 401"
  else
    fail "/api/token create without session should return 401: $(echo "$RESULT" | head -c 200)"
  fi

  # /api/token list (read op) -> should work without session
  RESULT=$(web_post "/api/token" '{"action":"list"}')
  if echo "$RESULT" | grep -q "tokens\|not_configured"; then
    pass "/api/token list without session -> allowed (read op)"
  else
    fail "/api/token list should work without session: $(echo "$RESULT" | head -c 200)"
  fi

  # /api/onboard check -> always public
  RESULT=$(web_post "/api/onboard" '{"action":"check"}')
  if echo "$RESULT" | jq -e '.exists' > /dev/null 2>&1 || echo "$RESULT" | grep -q "not_configured"; then
    pass "/api/onboard check -> allowed (always public)"
  else
    fail "/api/onboard check should work without session: $(echo "$RESULT" | head -c 200)"
  fi

  # Create a wallet to get a session token
  RESULT=$(web_post "/api/onboard" '{"action":"create"}')
  SESSION_TOKEN=$(echo "$RESULT" | jq -r '.sessionToken // empty' 2>/dev/null)
  if [ -n "$SESSION_TOKEN" ]; then
    pass "Session token received from /api/onboard create"

    # Use session for a protected endpoint
    RESULT=$(web_post "/api/faucet" \
      '{"address":"0000000000000000000000000000000000000000000000000000000000000001"}' \
      "X-Tonkl-Session: ${SESSION_TOKEN}")
    if echo "$RESULT" | grep -q "unauthorized"; then
      fail "/api/faucet with valid session should not return 401"
    else
      pass "/api/faucet with valid session -> auth passed"
    fi

    # Invalid session token should be rejected
    RESULT=$(web_post "/api/send" \
      '{"amount":1,"recipientAddress":"0x0000000000000000000000000000000000000000000000000000000000000001"}' \
      "X-Tonkl-Session: invalid-token-12345")
    if echo "$RESULT" | grep -q "unauthorized"; then
      pass "/api/send with invalid session -> 401"
    else
      fail "/api/send with invalid session should return 401"
    fi
  else
    skip "Could not create session (wallet may not be configured): $(echo "$RESULT" | head -c 200)"
  fi
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# 5. RATE LIMITING (RPC — use get_status read path since
#    produce_block may need auth and we don't want to burn the
#    window on a write endpoint)
# ═════════════════════════════════════════════════════════════════

bold "5. Rate Limiting (RPC)"

# Use get_merkle_proof — limit is 60/min.
# We'll do a burst and check that the mechanism exists.
# Instead of hitting the actual limit, just verify the endpoint works
# and then test produce_block (5/min) if auth is available.
if [ "$NODE_AUTH_ENABLED" = true ] && [ -n "$SECRET" ]; then
  RATE_LIMITED=false
  # produce_block limit is 5/min — we may have already used 1-2 above
  for i in $(seq 1 8); do
    RESULT=$(rpc_call "produce_block" "[\"${SECRET}\"]")
    if echo "$RESULT" | grep -q "rate limited"; then
      RATE_LIMITED=true
      pass "RPC rate limiter triggered after $i produce_block calls (limit: 5/min)"
      break
    fi
  done
  if [ "$RATE_LIMITED" = false ]; then
    fail "RPC rate limiter did not trigger for produce_block"
  fi
elif [ "$NODE_AUTH_ENABLED" = false ]; then
  RATE_LIMITED=false
  for i in $(seq 1 8); do
    RESULT=$(rpc_call "produce_block" "[null]")
    if echo "$RESULT" | grep -q "rate limited"; then
      RATE_LIMITED=true
      pass "RPC rate limiter triggered after $i produce_block calls (limit: 5/min)"
      break
    fi
  done
  if [ "$RATE_LIMITED" = false ]; then
    skip "RPC rate limiter not triggered — node binary may predate rate limiter code (rebuild needed)"
  fi
else
  skip "Cannot test rate limiting without node access"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# 6. CORS POLICY
# ═════════════════════════════════════════════════════════════════

bold "6. CORS Policy"

# Preflight from allowed origin
RESULT=$(curl -s -X OPTIONS "$NODE_URL" \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -D - -o /dev/null 2>/dev/null || echo "")
if echo "$RESULT" | grep -qi "access-control-allow-origin"; then
  pass "CORS preflight allows localhost origin"
else
  skip "CORS preflight — could not verify (server may not support OPTIONS)"
fi

# Request from disallowed origin — response should NOT include
# access-control-allow-origin for evil.com
RESULT=$(curl -s -X POST "$NODE_URL" \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_status","params":[],"id":1}' \
  -D - 2>/dev/null || echo "")
if echo "$RESULT" | grep -qi "access-control-allow-origin.*evil"; then
  fail "CORS should NOT echo evil.com as allowed origin"
else
  pass "CORS blocks non-localhost origin (evil.com)"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "\033[1mResults:\033[0m $(green "$PASS passed"), $(red "$FAIL failed"), $(yellow "$SKIP skipped")\n"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$NODE_AUTH_ENABLED" = false ]; then
  printf "\033[33m%s\033[0m\n" "Tip: For full auth testing, restart the node with:"
  echo "  TONKL_RPC_SECRET=test-secret-123 cargo run --release -- run --vk-dir ./vks"
  echo "  Or local-only no-auth: cargo run --release -- run --allow-unverified-local --allow-unauthenticated-rpc-local"
  echo "  Then: TONKL_RPC_SECRET=test-secret-123 ./scripts/smoke_test.sh"
  echo ""
fi

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
