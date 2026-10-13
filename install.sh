#!/usr/bin/env bash
# PASS VAULT Installer Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================="
echo "   PASS VAULT Installation & Setup      "
echo "========================================="

# 1. Check Python version
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is not installed. Please install Python (3.9+) first." >&2
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✓ Found Python $PY_VERSION"

# 2. Check/Install 'just' runner
if command -v just >/dev/null 2>&1; then
    echo "✓ Found 'just' command runner: $(just --version)"
else
    echo "→ 'just' is not installed. Installing 'just'..."
    mkdir -p "$HOME/.local/bin"
    if curl -sSf https://just.systems/install.sh | bash -s -- --to "$HOME/.local/bin" 2>/dev/null; then
        export PATH="$HOME/.local/bin:$PATH"
        echo "✓ 'just' installed to $HOME/.local/bin"
    elif command -v brew >/dev/null 2>&1; then
        brew install just
        echo "✓ 'just' installed via Homebrew"
    else
        echo "Note: Could not automatically download 'just'. You can use ./bin/pv directly."
    fi
fi

# 3. Check/Install 'uv' (or fall back to venv/pip)
USE_UV=false
if command -v uv >/dev/null 2>&1; then
    USE_UV=true
    echo "✓ Found 'uv' package manager: $(uv --version)"
else
    echo "→ Checking for 'uv' installer..."
    if (curl -LsSf https://astral.sh/uv/install.sh 2>/dev/null | sh 2>/dev/null) && [ -x "$HOME/.cargo/bin/uv" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
        USE_UV=true
        echo "✓ 'uv' installed successfully"
    else
        echo "→ Proceeding with Python standard venv & pip..."
    fi
fi

# 4. Set up Virtual Environment and Dependencies
echo "→ Configuring Python virtual environment (.venv)..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
if [ "$USE_UV" = true ]; then
    uv pip install argon2-cffi cryptography rich pytest pytest-cov || true
fi
.venv/bin/python setup.py develop --quiet
echo "✓ Dependencies installed successfully."

# 5. Set up 'pv' executable
chmod +x "$SCRIPT_DIR/bin/pv"
if mkdir -p "$HOME/.local/bin" 2>/dev/null && ln -sf "$SCRIPT_DIR/bin/pv" "$HOME/.local/bin/pv" 2>/dev/null; then
    echo "✓ Symlinked 'pv' to $HOME/.local/bin/pv"
else
    echo "✓ 'pv' executable is ready at ./bin/pv"
fi

echo ""
echo "========================================="
echo "   Installation Complete!               "
echo "========================================="
echo ""
echo "Ensure $HOME/.local/bin is in your PATH (e.g. export PATH=\"\$HOME/.local/bin:\$PATH\")."
echo ""
echo "Quick Start:"
echo "  1. Initialize vault:   pv init        (or: just run -- init)"
echo "  2. Add an entry:       pv add github  (or: just run -- add github)"
echo "  3. Retrieve entry:     pv get github  (or: just run -- get github)"
echo "  4. Generate password:  pv gen 32      (or: just run -- gen 32)"
echo "  5. Run tests:          just test"
echo ""
