# 🔐 [safepush](https://safepush.serghini.me/)

```
  ███████  █████  ███████ ███████ ██████  ██    ██ ███████ ██   ██
  ██      ██   ██ ██      ██      ██   ██ ██    ██ ██      ██   ██
  ███████ ███████ █████   █████   ██████  ██    ██ ███████ ███████
       ██ ██   ██ ██      ██      ██      ██    ██      ██ ██   ██
  ███████ ██   ██ ██      ███████ ██       ██████  ███████ ██   ██
```

**Git hooks that scan your code before it leaves your machine.**  
Better safe than sorry.

## Quick start

```bash
cd /path/to/your/project
curl -sSL https://raw.githubusercontent.com/simonserghini/safepush/main/install.sh | bash
```

That's it. Now every `git commit` and `git push` in that repo will run through the checks.

Or if you've cloned this repo:

```bash
./install.sh      # symlinks hooks from the cloned copy
```

## What it checks

### pre-commit (11 checks)

| Check | Severity | What it flags |
|-------|----------|---------------|
| Custom blocklist | BLOCK | Your personal patterns (emails, phones, secrets) |
| Secrets | BLOCK | API keys, tokens, passwords, AWS keys, GitHub PATs |
| Sensitive files | BLOCK | `.env`, `.pem`, `.key`, `id_rsa`, credentials |
| Large files | WARN | Files ≥ 1 MB |
| Merge conflicts | BLOCK | Leftover `<<<<<<<` markers |
| Debug prints | WARN | `console.log`, `println!`, `fmt.Println`, `puts`… |
| Trailing whitespace | WARN | Offers to strip in-place |
| Lockfile drift | WARN | Manifest changed, lockfile didn't |
| Hardcoded connections | WARN | DB URLs, raw IPs |
| Absolute paths | INFO | `/home/…` paths that break elsewhere |
| TODO / FIXME | INFO | Forgotten markers |

### pre-push (5 checks)

| Check | Severity | What it flags |
|-------|----------|---------------|
| Force push | BLOCK | History rewrite on remote |
| Protected branch | WARN | Direct push to `main`/`master` |
| Unstaged changes | WARN | Modified files not staged |
| Commit messages | INFO | Messages under 8 characters |
| Untracked files | INFO | Files you might have forgotten |

## Custom blocklist

Create a `.safepush-blocklist` file in your repo root with one pattern per line:

```
# .safepush-blocklist — these patterns will BLOCK the commit
simon@example.com
\+1-555-\d{3}-\d{4}
internal\.company\.com
```

Lines starting with `#` are comments.  Uses `grep -E` regex.

## Interactive mode

All checks are interactive when run in a terminal — they ask `[y/N]` before blocking.
In CI or scripts (non-TTY), all checks pass through without blocking.

## Language support

Debug-prints check covers: JavaScript/TS, Rust, Python, Go, Java, C#, Ruby, Kotlin, PHP, C/C++, Bash.

https://safepush.serghini.me/
