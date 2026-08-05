#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOTNET_DIR="$SCRIPT_DIR/.dotnet"
DOTNET="$DOTNET_DIR/dotnet"

install_dotnet() {
    if [ -x "$DOTNET" ] && "$DOTNET" --list-sdks 2>/dev/null | grep -q "8.0"; then
        echo "[OK] .NET SDK 8.0 already installed at $DOTNET_DIR"
        return
    fi
    echo "[...] Installing .NET SDK 8.0 to $DOTNET_DIR ..."
    mkdir -p "$DOTNET_DIR"
    wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh
    chmod +x /tmp/dotnet-install.sh
    /tmp/dotnet-install.sh --channel 8.0 --install-dir "$DOTNET_DIR" --no-path
    rm -f /tmp/dotnet-install.sh
    echo "[OK] .NET SDK 8.0 installed"
}

check_env() {
    echo "=== Environment Check ==="
    if command -v cmake &>/dev/null; then
        echo "[OK] cmake: $(cmake --version | head -1)"
    else
        echo "[FAIL] cmake not found"
    fi
    if command -v g++ &>/dev/null; then
        echo "[OK] g++: $(g++ --version | head -1)"
    else
        echo "[FAIL] g++ not found"
    fi
    if command -v make &>/dev/null; then
        echo "[OK] make: $(make --version | head -1)"
    else
        echo "[FAIL] make not found"
    fi
    echo ""
}

check_env
install_dotnet
echo ""
echo "[DONE] Environment ready. Use $DOTNET for builds."
echo "       Export PATH:  export PATH=\"$DOTNET_DIR:\$PATH\""
