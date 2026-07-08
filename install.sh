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

# ── CLI flags ──────────────────────────────────────────────────
UNINSTALL=false
FORCE=false

for arg in "$@"; do
    case "$arg" in
        --uninstall)                UNINSTALL=true ;;
        --remove-blocklist|-y|--yes) FORCE=true ;;
        -h|--help)
            echo ""
            echo "  safepush installer"
            echo ""
            echo "  Usage:"
            echo "    ./install.sh               Install hooks + interactive blocklist setup"
            echo "    ./install.sh --uninstall   Remove safepush hooks from this repo"
            echo "    ./install.sh --uninstall --remove-blocklist   Also delete .safepush-blocklist"
            echo ""
            exit 0
            ;;
        *)
            echo "  Unknown flag: $arg   (try --help)"
            exit 1
            ;;
    esac
done

# ── Uninstall ──────────────────────────────────────────────────
if $UNINSTALL; then
    removed=0

    uninstall_hook() {
        local name="$1"
        local target="$HOOKS_DIR/$name"

        if [ -f "$target" ] || [ -L "$target" ]; then
            if grep -qi 'safepush' "$target" 2>/dev/null; then
                rm -f "$target"
                echo "  ✓ removed $name"
                removed=$((removed + 1))
            else
                echo "  ⓘ  $name is not a safepush hook — skipping"
            fi
        else
            echo "  ⓘ  $name not found — nothing to do"
        fi
    }

    echo ""
    echo "  🔐 safepush — uninstalling…"
    echo ""

    uninstall_hook "pre-commit"
    uninstall_hook "pre-push"

    # Blocklist
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
    BLOCKLIST="$REPO_ROOT/.safepush-blocklist"

    if [ -f "$BLOCKLIST" ]; then
        if $FORCE; then
            rm -f "$BLOCKLIST"
            echo "  ✓ removed .safepush-blocklist"
        elif [ -t 0 ]; then
            echo ""
            echo -n "  Remove .safepush-blocklist too? [y/N] "
            read -r answer || true
            if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
                rm -f "$BLOCKLIST"
                echo "  ✓ removed .safepush-blocklist"
            else
                echo "  ⓘ  kept .safepush-blocklist"
            fi
        else
            echo "  ⓘ  .safepush-blocklist exists (use --remove-blocklist to remove)"
        fi
    fi

    echo ""
    echo "  Done — $removed hook(s) removed."
    echo ""
    exit 0
fi

# ── Helper — is this a safepush hook? ──────────────────────────
is_safepush_hook() {
    local hook_path="$1"
    [ -f "$hook_path" ] || [ -L "$hook_path" ] || return 1
    grep -qi 'safepush' "$hook_path" 2>/dev/null
}

# ── Already installed? ─────────────────────────────────────────
# Check if safepush hooks are already in .git/hooks/.
# If so, offer to reinstall or uninstall (interactive only).
ALREADY_INSTALLED=false
if is_safepush_hook "$HOOKS_DIR/pre-commit" && is_safepush_hook "$HOOKS_DIR/pre-push"; then
    ALREADY_INSTALLED=true
fi

if $ALREADY_INSTALLED; then
    echo ""
    echo "  🔐 safepush is already installed in this repo."

    if [ -t 0 ]; then
        echo ""
        echo "  What would you like to do?"
        echo "    [R] reinstall  — replace hooks with the latest version"
        echo "    [U] uninstall  — remove safepush from this repo"
        echo "    [Q] quit       — leave everything as-is"
        echo ""
        echo -n "  [R/u/q]: "
        read -r choice || true
        choice=$(echo "$choice" | xargs | tr '[:upper:]' '[:lower:]')

        case "$choice" in
            u|uninstall)
                UNINSTALL=true
                FORCE=false
                ;;
            r|reinstall|"")
                # Proceed with install below — hooks will be replaced.
                ;;
            q|quit)
                echo "  ✗ cancelled"
                exit 0
                ;;
            *)
                echo "  ⓘ  unrecognized choice — reinstalling"
                ;;
        esac

        if $UNINSTALL; then
            # Reuse the uninstall logic inline.
            removed=0

            uninstall_hook() {
                local name="$1"
                local target="$HOOKS_DIR/$name"
                if is_safepush_hook "$target"; then
                    rm -f "$target"
                    echo "  ✓ removed $name"
                    removed=$((removed + 1))
                else
                    echo "  ⓘ  $name is not a safepush hook — skipping"
                fi
            }

            echo ""
            echo "  🔐 safepush — uninstalling…"
            echo ""

            uninstall_hook "pre-commit"
            uninstall_hook "pre-push"

            REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
            BLOCKLIST="$REPO_ROOT/.safepush-blocklist"

            if [ -f "$BLOCKLIST" ]; then
                echo ""
                echo -n "  Remove .safepush-blocklist too? [y/N] "
                read -r answer || true
                if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
                    rm -f "$BLOCKLIST"
                    echo "  ✓ removed .safepush-blocklist"
                else
                    echo "  ⓘ  kept .safepush-blocklist"
                fi
            fi

            echo ""
            echo "  Done — $removed hook(s) removed."
            echo ""
            exit 0
        fi
    else
        echo "  ⓘ  non-interactive — reinstalling with latest hooks."
    fi
fi

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

# ── Helper — escape a string for grep -E regex ─────────────────
escape_regex() {
    echo "$1" | sed -e 's/\./\\./g'  -e 's/\+/\\+/g'  -e 's/\*/\\*/g' \
                   -e 's/\?/\\?/g'  -e 's/(/\\(/g'   -e 's/)/\\)/g' \
                   -e 's/\[/\\[/g'  -e 's/\]/\\]/g'  -e 's/{/\\{/g' \
                   -e 's/}/\\}/g'   -e 's/|/\\|/g'   -e 's/\^/\\^/g' \
                   -e 's/\$/\\$/g'
}

# ── Interactive blocklist ──────────────────────────────────────
setup_blocklist() {
    local blocklist="$REPO_ROOT/.safepush-blocklist"
    local header_written=false

    # Seed the file with a header if it doesn't exist yet.
    if [ ! -f "$blocklist" ]; then
        {
            echo "# .safepush-blocklist — patterns that will BLOCK the commit"
            echo "# This file lives on your machine. It is never sent anywhere."
            echo "# Edit anytime to add or remove patterns."
            echo ""
        } > "$blocklist"
        header_written=true
    fi

    echo ""
    echo "  ── Personal blocklist ──"
    echo ""
    echo "  The blocklist catches sensitive info BEFORE it leaves"
    echo "  your machine.  Any file that matches a pattern here"
    echo "  will be BLOCKED from being committed."
    echo ""
    echo "  This file (.safepush-blocklist) stays local."
    echo "  Nothing is uploaded or shared."
    echo ""

    # -- Email(s) --
    echo -n "  Your email(s)  [comma-separated, or enter to skip]: "
    read -r raw_emails || true
    raw_emails=$(echo "$raw_emails" | xargs)
    if [ -n "$raw_emails" ]; then
        echo "# Emails" >> "$blocklist"
        IFS=',' read -ra EMAILS <<< "$raw_emails"
        for email in "${EMAILS[@]}"; do
            email=$(echo "$email" | xargs)
            [ -z "$email" ] && continue
            escaped=$(escape_regex "$email")
            echo "$escaped" >> "$blocklist"
            echo "    ✓ $email"
        done
    fi

    # -- Phone number(s) --
    echo -n "  Your phone(s)  [comma-separated, or enter to skip]: "
    read -r raw_phones || true
    raw_phones=$(echo "$raw_phones" | xargs)
    if [ -n "$raw_phones" ]; then
        echo "# Phone numbers" >> "$blocklist"
        IFS=',' read -ra PHONES <<< "$raw_phones"
        for phone in "${PHONES[@]}"; do
            phone=$(echo "$phone" | xargs)
            [ -z "$phone" ] && continue
            escaped=$(escape_regex "$phone")
            echo "$escaped" >> "$blocklist"
            echo "    ✓ $phone"
        done
    fi

    # -- Custom patterns (free-form, one per line) --
    echo ""
    echo "  Add any other patterns (one per line, blank to finish):"
    echo "# Custom patterns" >> "$blocklist"
    local n=1
    while true; do
        echo -n "    $n: "
        read -r pattern || break
        pattern=$(echo "$pattern" | xargs)
        if [ -z "$pattern" ]; then
            break
        fi
        echo "$pattern" >> "$blocklist"
        echo "    ✓ added"
        n=$((n + 1))
    done

    echo ""
    echo "  ✓ .safepush-blocklist saved"
}

# Only run interactively when stdin is a terminal.
# In CI or pipe mode, skip and let the user edit manually.
if [ -t 0 ]; then
    setup_blocklist
else
    # Fall back: download the example blocklist.
    if [ ! -f "$REPO_ROOT/.safepush-blocklist" ]; then
        if curl -sSLf "$BASE_URL/.safepush-blocklist" -o "$REPO_ROOT/.safepush-blocklist" 2>/dev/null; then
            echo ""
            echo "  ✓ .safepush-blocklist (example — edit with your patterns)"
        fi
    fi
fi

# ── All done! ─────────────────────────────────────────────────
echo ""
echo "  Done — $installed hook(s) installed."
echo ""
echo "  Review .safepush-blocklist anytime to add or remove patterns."
echo ""
