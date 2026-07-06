#!/usr/bin/env sh
# comwatch — POSIX installer (Linux / macOS)
# Builds a self-contained binary and installs it to a bin dir on PATH.
# Requires the .NET 8 SDK. Usage: ./install.sh [--prefix DIR]
set -eu

PREFIX="${PREFIX:-$HOME/.local}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --prefix=*) PREFIX="${1#*=}"; shift ;;
        -h|--help) echo "usage: install.sh [--prefix DIR]  (default: \$HOME/.local)"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if ! command -v dotnet >/dev/null 2>&1; then
    echo "error: dotnet SDK not found. Install .NET 8: https://dotnet.microsoft.com/download" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
BINDIR="$PREFIX/bin"
mkdir -p "$BINDIR"

echo "building self-contained comwatch..."
dotnet publish "$HERE/comwatch.csproj" -c Release \
    -p:PublishSingleFile=true --self-contained true -o "$HERE/dist" >/dev/null

# The published binary is named 'comwatch' (AssemblyName).
BIN="$HERE/dist/comwatch"
[ -f "$BIN" ] || BIN="$HERE/dist/comwatch.exe"
install -m 0755 "$BIN" "$BINDIR/comwatch" 2>/dev/null || cp "$BIN" "$BINDIR/comwatch"
chmod +x "$BINDIR/comwatch" 2>/dev/null || true

echo "installed: $BINDIR/comwatch"
echo "ensure $BINDIR is on your PATH, then: comwatch --selftest"
