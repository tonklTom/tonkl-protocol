#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PASS=0
FAIL=0
SKIP=0

green() { printf "\033[32m%s\033[0m" "$1"; }
red() { printf "\033[31m%s\033[0m" "$1"; }
yellow() { printf "\033[33m%s\033[0m" "$1"; }
bold() { printf "\033[1m%s\033[0m\n" "$1"; }

pass() {
  PASS=$((PASS + 1))
  printf "  %s %s\n" "$(green PASS)" "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  printf "  %s %s\n" "$(red FAIL)" "$1"
}

skip() {
  SKIP=$((SKIP + 1))
  printf "  %s %s\n" "$(yellow SKIP)" "$1"
}

run_required() {
  local label="$1"
  shift
  bold "$label"
  if "$@"; then
    pass "$label"
  else
    fail "$label"
  fi
  echo ""
}

run_optional_nargo() {
  local package_dir="$1"
  local label
  label="nargo test ${package_dir}"

  if ! command -v nargo >/dev/null 2>&1; then
    skip "$label (nargo not installed)"
    return
  fi

  bold "$label"
  if (cd "$ROOT_DIR/$package_dir" && nargo test); then
    pass "$label"
  else
    fail "$label"
  fi
  echo ""
}

bold "Tonkl ZK Security Audit"
echo "Root: $ROOT_DIR"
echo ""

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required for Rust node/prover security tests"
else
  run_required "cargo test -p tonkl-node public input and state guards" \
    cargo test --manifest-path "$ROOT_DIR/tonkl-node/Cargo.toml"

  run_required "cargo test -p tonkl-prover witness compatibility" \
    cargo test --manifest-path "$ROOT_DIR/tonkl-prover/Cargo.toml"
fi

run_optional_nargo "tonkl-lib"
run_optional_nargo "tonkl-transfer"
run_optional_nargo "tonkl-split"
run_optional_nargo "tonkl-merge"
run_optional_nargo "tonkl-mint"

bold "Summary"
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  red "ZK security audit failed."
  echo ""
  exit 1
fi

echo ""
green "ZK security audit completed."
echo ""
