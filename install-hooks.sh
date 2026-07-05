#!/usr/bin/env bash
# install-hooks.sh — symlinks all hooks from hooks/ into .git/hooks/
# Run once after cloning:  ./install-hooks.sh

set -euo pipefail

HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)/hooks"
GIT_HOOKS="$(cd "$(dirname "$0")" && pwd)/.git/hooks"

if [ ! -d "$GIT_HOOKS" ]; then
    echo "error: not a git repository (no .git/hooks/)"
    exit 1
fi

installed=0

for hook in "$HOOKS_DIR"/*; do
    name="$(basename "$hook")"
    target="$GIT_HOOKS/$name"

    # Remove existing hook (file or symlink)
    if [ -e "$target" ] || [ -L "$target" ]; then
        rm "$target"
    fi

    ln -s "$hook" "$target"
    chmod +x "$hook"
    echo "  installed  $name"
    installed=$((installed + 1))
done

echo ""
echo "Done — $installed hook(s) installed."
