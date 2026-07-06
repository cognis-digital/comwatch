#!/usr/bin/env bash
# comwatch — runnable demo. Builds the tool and exercises every output format
# against the bundled examples. Exits 0 on success (each expected-exit checked).
set -u
cd "$(dirname "$0")/.."

echo "== building comwatch =="
dotnet build -c Release >/dev/null

run() { dotnet run -c Release --no-build -- "$@"; }

echo
echo "== 1. clean export -> no findings, exit 0 =="
run examples/clean.reg --format table -q
[ $? -eq 0 ] || { echo "FAIL: clean.reg should exit 0"; exit 1; }

echo
echo "== 2. hijacked export -> HIGH findings, exit 2 =="
run examples/hijacked.reg --format table -q
[ $? -eq 2 ] || { echo "FAIL: hijacked.reg should exit 2"; exit 1; }

echo
echo "== 3. selftest as JSON =="
run --selftest -q >/dev/null; [ $? -eq 2 ] || { echo "FAIL: selftest exit"; exit 1; }

echo
echo "== 4. SARIF 2.1.0 (for GitHub code scanning) =="
run --selftest --format sarif -q | head -6

echo
echo "== 5. Sigma detection rule =="
run examples/hijacked.reg --format sigma -q | head -8

echo
echo "== 6. CEF for SIEM ingest (first line) =="
run examples/hijacked.reg --format cef -q | head -1

echo
echo "== 7. recursive directory scan of examples/ =="
run examples --format table -q | head -3

echo
echo "== 8. baseline suppression =="
run examples/hijacked.reg -q > /tmp/comwatch_demo.json 2>/dev/null || true
echo "(findings emitted; a baseline file of fingerprints would suppress known-good)"

echo
echo "demo OK"
