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

## ☁️ Cloud scanner

Scan any GitHub repo — or your entire profile — for secrets, API keys, tokens, debug prints, and more. Runs on Cloudflare Workers. No install needed.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/simonserghini/safepush)

Click the button above, then:

```bash
# Scan a single repo
curl -X POST https://your-worker.workers.dev/scan \
  -H 'content-type: application/json' \
  -d '{"owner":"simonserghini","repo":"safepush"}'

# Scan an entire GitHub profile
curl -X POST https://your-worker.workers.dev/scan-profile \
  -H 'content-type: application/json' \
  -d '{"username":"some-user"}'

# Add a webhook to scan every push automatically
# (GitHub → Settings → Webhooks → Payload URL: https://your-worker.workers.dev/webhook)
```

Supply a GitHub token via the `x-github-token` header to scan private repos.

## Custom blocklist

Create a `.safepush-blocklist` file in your repo root with one pattern per line:

```
# .safepush-blocklist — these patterns will BLOCK the commit
simon@example.com
\+1-555-\d{3}-\d{4}
internal\.company\.com
```

Lines starting with `#` are comments.  Uses `grep -E` regex.

https://safepush.serghini.me/
