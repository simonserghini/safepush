#!/usr/bin/env bash
# ┌─────────────────────────────────────────────────────────────┐
# │  safepush — one-liner installer                            │
# │                                                             │
# │  No cloning, no dependencies, no build step.               │
# │  Just curl this into your project and you're protected.    │
# │                                                             │
# │  Usage:                                                     │
# │    cd /path/to/your/project                                 │
# │    curl -sSL https://raw.../safepush/main/install.sh | bash │
# │                                                             │
# │  Or if you already cloned safepush:                        │
# │    ./install.sh                                             │
# └─────────────────────────────────────────────────────────────┘
set -euo pipefail

# ── Where to fetch from on GitHub ─────────────────────────────
# If you forked safepush, change these to point to your copy.
GITHUB_USER="${GITHUB_USER:-simonserghini}"
GITHUB_REPO="${GITHUB_REPO:-safepush}"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
BASE_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}"

# ── Make sure we're inside a git repo ─────────────────────────
# We need somewhere to put the hooks!
GIT_DIR=$(git rev-parse --git-dir 2>/dev/null) || {
    echo "error: not in a git repository"
    echo "  cd /path/to/your/project   then run this again"
    exit 1
}

# This is where git keeps its hooks — every repo has one.
HOOKS_DIR="${GIT_DIR}/hooks"

# ── Are we inside a safepush clone, or just some project? ────
# If the hooks already exist locally, we symlink them (faster,
# and edits to the source take effect immediately).
# If not, we download them fresh from GitHub.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
LOCAL=false
if [ -f "$REPO_ROOT/hooks/pre-commit" ] && [ -f "$REPO_ROOT/hooks/pre-push" ]; then
    if grep -q 'hooks/pre-commit' "$REPO_ROOT/hooks/pre-commit" 2>/dev/null; then
        LOCAL=true
    fi
fi

# ── The actual install — put a hook into .git/hooks/ ──────────
installed=0

install_hook() {
    local name="$1"
    local target="$HOOKS_DIR/$name"

    # If there's already a hook here (from another tool or a
    # previous install), remove it so we don't conflict.
    [ -e "$target" ] || [ -L "$target" ] && rm -f "$target"

    if $LOCAL; then
        # We're inside the safepush repo — just symlink.
        ln -s "$REPO_ROOT/hooks/$name" "$target"
        chmod +x "$REPO_ROOT/hooks/$name"
    else
        # Download from GitHub's raw file server.
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

# Install both hooks.
install_hook "pre-commit"
install_hook "pre-push"

# ── Give them an example blocklist ────────────────────────────
# Only if they don't already have one.  They should edit this
# with their own patterns.
if [ ! -f "$REPO_ROOT/.safepush-blocklist" ]; then
    if curl -sSLf "$BASE_URL/.safepush-blocklist" -o "$REPO_ROOT/.safepush-blocklist" 2>/dev/null; then
        echo "  ✓ .safepush-blocklist (example — edit with your patterns)"
    fi
fi

# ── All done! ─────────────────────────────────────────────────
echo ""
echo "  Done — $installed hook(s) installed."
echo ""
echo "  Next: edit .safepush-blocklist with your personal patterns"
echo "        (emails, phone numbers, project names you never want to leak)"
echo ""
