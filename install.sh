#!/usr/bin/env bash
# install.sh — one-liner installer for safepush.
#
# Usage:
#   cd /path/to/your/project
#   curl -sSL https://raw.githubusercontent.com/simon/safepush/master/install.sh | bash
#
# Or if you've cloned the repo:
#   ./install.sh
#
# Installs pre-commit and pre-push hooks into .git/hooks/ of the current repo.

set -euo pipefail

# ── Config ─────────────────────────────────────────────────────
# Change this to your fork if you host your own copy.
GITHUB_USER="${GITHUB_USER:-simon}"
GITHUB_REPO="${GITHUB_REPO:-safepush}"
GITHUB_BRANCH="${GITHUB_BRANCH:-master}"
BASE_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}"

# ── Check we're in a git repo ──────────────────────────────────
GIT_DIR=$(git rev-parse --git-dir 2>/dev/null) || {
    echo "error: not in a git repository"
    echo "  cd /path/to/your/project   then run this again"
    exit 1
}

HOOKS_DIR="${GIT_DIR}/hooks"

# ── Detect if we're inside a cloned safepush repo ──────────
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
LOCAL=false
if [ -f "$REPO_ROOT/hooks/pre-commit" ] && [ -f "$REPO_ROOT/hooks/pre-push" ]; then
    # Check if it looks like safepush
    if grep -q 'hooks/pre-commit' "$REPO_ROOT/hooks/pre-commit" 2>/dev/null; then
        LOCAL=true
    fi
fi

# ── Install hooks ──────────────────────────────────────────────
installed=0

install_hook() {
    local name="$1"
    local target="$HOOKS_DIR/$name"

    # Remove existing hook (file or symlink)
    [ -e "$target" ] || [ -L "$target" ] && rm -f "$target"

    if $LOCAL; then
        # Symlink from cloned repo
        ln -s "$REPO_ROOT/hooks/$name" "$target"
        chmod +x "$REPO_ROOT/hooks/$name"
    else
        # Download from GitHub
        if curl -sSLf "$BASE_URL/hooks/$name" -o "$target"; then
            chmod +x "$target"
        else
            echo "  failed to download $name — check your network or GITHUB_USER/REPO"
            return 1
        fi
    fi

    echo "  ✓ $name"
    installed=$((installed + 1))
}

echo ""
echo "  🔐 safepush — installing hooks…"
echo ""

install_hook "pre-commit"
install_hook "pre-push"

# ── Create example blocklist if none exists ────────────────────
if [ ! -f "$REPO_ROOT/.safepush-blocklist" ]; then
    if curl -sSLf "$BASE_URL/.safepush-blocklist" -o "$REPO_ROOT/.safepush-blocklist" 2>/dev/null; then
        echo "  ✓ .safepush-blocklist (example — edit with your patterns)"
    fi
fi

# ── Done ───────────────────────────────────────────────────────
echo ""
echo "  Done — $installed hook(s) installed."
echo ""
echo "  Next: edit .safepush-blocklist with your personal patterns"
echo "        (emails, phone numbers, project names you never want to leak)"
echo ""
