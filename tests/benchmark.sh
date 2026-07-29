#!/bin/bash
set -e

echo "==============================================="
echo "Bulx Benchmark & Validation Suite"
echo "==============================================="

if ! command -v hyperfine &> /dev/null; then
    echo "Installing hyperfine..."
    cargo install hyperfine
fi

# Ensure bulx is built in release mode for accurate benchmarking
echo "Building Bulx in release mode..."
cargo build --release
BULX="./target/release/bulx"

echo ""
echo "[1] Testing Startup Latency (No-op Command)"
echo "-----------------------------------------------"
hyperfine --warmup 3 \
    --export-markdown benchmark_startup.md \
    "echo 'hello'" \
    "$BULX --enforce echo 'hello'" \
    "$BULX --audit echo 'hello'"

echo ""
echo "[2] Testing High I/O Overhead (File enumeration)"
echo "-----------------------------------------------"
hyperfine --warmup 1 \
    --export-markdown benchmark_io.md \
    "find /usr -type f 2>/dev/null | head -n 10000" \
    "$BULX --enforce find /usr -type f 2>/dev/null | head -n 10000" \
    "$BULX --audit find /usr -type f 2>/dev/null | head -n 10000"

echo ""
echo "Benchmarks Complete! Results saved to benchmark_*.md"
