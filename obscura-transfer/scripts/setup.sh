#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# Obscura Transfer Circuit — Development Environment Setup
# ═══════════════════════════════════════════════════════════════════════════
# Run this once after cloning to install Nargo and bb (Barretenberg).
# Tested on macOS (Apple Silicon + Intel) and Ubuntu 22.04.
#
# What gets installed:
#   nargo    — Noir compiler and prover CLI
#   bb       — Barretenberg backend for Groth16/UltraPlonk proving
#   noirup   — Version manager for Nargo (like rustup for Rust)
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

NARGO_TARGET_VERSION="0.31.0"  # Pin to whitepaper-compatible version

echo "═══════════════════════════════════════════════════════"
echo "  Obscura Transfer — Environment Setup"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── 1. Install noirup (Nargo version manager) ─────────────────────────────
echo "[1/4] Installing noirup..."
if command -v noirup &>/dev/null; then
    echo "  noirup already installed — skipping"
else
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
    # Add to PATH for this session
    export PATH="$HOME/.nargo/bin:$PATH"
    echo "  ✓ noirup installed"
fi

# ── 2. Install Nargo ──────────────────────────────────────────────────────
echo "[2/4] Installing Nargo v${NARGO_TARGET_VERSION}..."
if command -v nargo &>/dev/null; then
    INSTALLED=$(nargo --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ "$INSTALLED" = "$NARGO_TARGET_VERSION" ]; then
        echo "  Nargo v${NARGO_TARGET_VERSION} already installed — skipping"
    else
        echo "  Updating from v${INSTALLED} to v${NARGO_TARGET_VERSION}..."
        noirup -v "$NARGO_TARGET_VERSION"
    fi
else
    noirup -v "$NARGO_TARGET_VERSION"
fi
echo "  ✓ $(nargo --version)"

# ── 3. Install Barretenberg backend (bb) ─────────────────────────────────
echo "[3/4] Installing Barretenberg backend (bb)..."
if command -v bb &>/dev/null; then
    echo "  bb already installed — skipping"
    bb --version 2>/dev/null || true
else
    # bbup is the Barretenberg version manager
    curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
    export PATH="$HOME/.bb:$PATH"
    bbup  # installs latest compatible version
    echo "  ✓ bb installed"
fi

# ── 4. Python witness generator dependencies ──────────────────────────────
echo "[4/4] Installing Python witness generator dependencies..."
if command -v pip3 &>/dev/null; then
    pip3 install poseidon-hash --quiet 2>/dev/null && \
        echo "  ✓ poseidon-hash installed" || \
        echo "  ⚠ poseidon-hash install failed — mock hash will be used (circuit structure testing only)"
else
    echo "  ⚠ pip3 not found — skipping Python deps (witness generator will use mock hash)"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Setup complete. Next steps:"
echo ""
echo "  1. Generate a test witness:"
echo "       python3 scripts/generate_witness.py"
echo ""
echo "  2. Check the circuit compiles:"
echo "       nargo check"
echo ""
echo "  3. Run circuit unit tests:"
echo "       nargo test"
echo ""
echo "  4. Generate a proof:"
echo "       nargo prove"
echo ""
echo "  5. Verify the proof:"
echo "       nargo verify"
echo "═══════════════════════════════════════════════════════"
