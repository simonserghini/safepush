/**
 * safepush Cloudflare Worker — cloud secret scanner.
 *
 * Auth:
 *   GET  /login            — GitHub OAuth login
 *   GET  /callback          — OAuth callback
 *   GET  /auth/status       — Check current session
 *
 * Scanning:
 *   POST /scan              — Scan a single repo
 *   POST /scan-profile      — Scan all repos for a user
 *   POST /scan-installations— Scan all repos across all app installations
 *
 * CI / webhooks:
 *   POST /webhook           — GitHub webhook receiver (verified)
 *   POST /webhook/setup     — Instructions for setting up webhooks
 *
 * Results:
 *   GET  /dashboard/:owner  — Profile scan results
 *   GET  /scan/:owner/:repo — Single repo results
 *   GET  /                  — Landing page with login
 */

import { scanFile, summarize, ScanResult, ScanMatch } from "./scanner";
import {
  getRepoInfo, listRepoFiles, getFileContent, listUserRepos, getPushDiff,
  verifyWebhookSignature, getOAuthURL, exchangeOAuthCode, getOAuthUser,
  createCommitStatus, createCheckRun, listAppInstallations, listInstallationRepos,
} from "./github";

export interface Env {
  SCANS: KVNamespace;
  SESSIONS: KVNamespace;
  DASHBOARD_TITLE: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  WEBHOOK_SECRET: string;
  BASE_URL: string;
}

// ── SARIF export ──────────────────────────────────────────

function toSarif(result: ScanResult): any {
  const rules = new Map<string, { id: string; name: string; severity: string }>();
  const results: any[] = [];

  for (const m of result.matches) {
    const ruleId = m.check;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: m.check.replace(/_/g, " "),
        severity: m.severity === "BLOCK" ? "error" : m.severity === "WARN" ? "warning" : "note",
      });
    }
    results.push({
      ruleId,
      message: { text: `${m.pattern}: ${m.line}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: m.path },
          region: { startLine: m.lineNumber || 1 },
        },
      }],
    });
  }

  return {
    version: "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "safepush",
          informationUri: "https://safepush.serghini.me",
          rules: Array.from(rules.values()),
        },
      },
      results,
    }],
  };
}

function json(body: any, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function cors(request: Request): Record<string, string> {
  const origin = request.headers.get("origin") || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers":
      "content-type, authorization, x-github-token, x-safepush-session",
  };
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

// ── Token extraction ──────────────────────────────────────

async function extractToken(request: Request, env: Env): Promise<string | undefined> {
  // 1. Authorization header (Bearer token)
  const auth = request.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);

  // 2. Custom header
  const headerToken = request.headers.get("x-github-token");
  if (headerToken) return headerToken;

  // 3. Session cookie / header
  const sessionId = getSessionCookie(request)
    || request.headers.get("x-safepush-session");
  if (sessionId) {
    const stored = await env.SESSIONS.get(`session:${sessionId}`);
    if (stored) return stored;
  }

  // 4. Request body
  try {
    const body = await request.clone().json() as any;
    if (body.token) return body.token;
  } catch {}

  // 5. Query string
  const url = new URL(request.url);
  const queryToken = url.searchParams.get("token");
  if (queryToken) return queryToken;

  return undefined;
}

// ── Logout ─────────────────────────────────────────────────

function handleLogout(): Response {
  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/",
      "Set-Cookie": "safepush_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
    },
  });
}

// ── OAuth ──────────────────────────────────────────────────

async function handleLogin(request: Request, env: Env): Promise<Response> {
  if (!env.GITHUB_CLIENT_ID) {
    return html("<h1>OAuth not configured</h1><p>Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET env vars.</p>", 500);
  }
  const state = crypto.randomUUID();
  const url = getOAuthURL(env.GITHUB_CLIENT_ID, `${env.BASE_URL}/callback`, state);

  // Store state for CSRF protection
  await env.SESSIONS.put(`oauth:${state}`, "pending", { expirationTtl: 600 });

  return Response.redirect(url, 302);
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return html("<h1>Missing code or state</h1>", 400);
  }

  // Verify state
  const stateCheck = await env.SESSIONS.get(`oauth:${state}`);
  if (!stateCheck) {
    return html("<h1>Invalid state — possible CSRF attack</h1>", 400);
  }
  await env.SESSIONS.delete(`oauth:${state}`);

  const token = await exchangeOAuthCode(code, env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET);
  if (!token) {
    return html("<h1>Failed to exchange code for token</h1>", 500);
  }

  const username = await getOAuthUser(token);
  if (!username) {
    return html("<h1>Failed to get user info</h1>", 500);
  }

  // Create session
  const sessionId = crypto.randomUUID();
  await env.SESSIONS.put(`session:${sessionId}`, token, { expirationTtl: 86400 });
  await env.SESSIONS.put(`user:${sessionId}`, username, { expirationTtl: 86400 });

  // Set session cookie and redirect to dashboard
  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/",
      "Set-Cookie": `safepush_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
    },
  });
}

async function handleAuthStatus(request: Request, env: Env): Promise<Response> {
  const sessionId = request.headers.get("x-safepush-session")
    || new URL(request.url).searchParams.get("session");
  if (!sessionId) return json({ authenticated: false, message: "No session provided" });

  const token = await env.SESSIONS.get(`session:${sessionId}`);
  if (!token) return json({ authenticated: false, message: "Invalid or expired session" });

  const username = await getOAuthUser(token);
  return json({ authenticated: true, username, expires: "24h" });
}

// ── Scanning ──────────────────────────────────────────────

async function scanRepo(
  owner: string, repo: string, token?: string
): Promise<ScanResult> {
  const info = await getRepoInfo(owner, repo, token);
  if (!info) throw new Error(`Repo ${owner}/${repo} not found or access denied`);

  // Fetch .safepushignore from repo root for path-level ignores
  let ignorePaths: string[] = [];
  try {
    const ignoreContent = await getFileContent(owner, repo, ".safepushignore", info.defaultBranch, token);
    if (ignoreContent) {
      ignorePaths = ignoreContent.split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#"));
    }
  } catch {}

  const files = await listRepoFiles(owner, repo, info.defaultBranch, token);
  const allMatches: ScanMatch[] = [];

  const maxFiles = Math.min(files.length, 500);
  for (let i = 0; i < maxFiles; i++) {
    const f = files[i];
    if (f.size > 1_000_000) continue;
    const skipDirs = ["node_modules/", "dist/", "build/", ".git/", "target/",
                      "__pycache__/", ".next/", "vendor/", "bower_components/"];
    if (skipDirs.some((d) => f.path.startsWith(d))) continue;

    try {
      const content = await getFileContent(owner, repo, f.path, info.defaultBranch, token);
      if (content) {
        allMatches.push(...scanFile(f.path, content, { ignorePaths }));
      }
    } catch {}
  }

  return {
    repo: `${owner}/${repo}`,
    scannedAt: new Date().toISOString(),
    totalFiles: maxFiles,
    matches: allMatches,
    summary: summarize(allMatches),
  };
}

async function handleScan(request: Request, env: Env): Promise<Response> {
  let body: any;
  try { body = await request.json(); } catch { return json({ error: "invalid JSON body" }, 400); }

  const { owner, repo } = body;
  if (!owner || !repo) return json({ error: "owner and repo are required" }, 400);

  const token = await extractToken(request, env);
  const format = new URL(request.url).searchParams.get("format");

  try {
    const result = await scanRepo(owner, repo, token);
    await env.SCANS.put(`scan:${owner}:${repo}`, JSON.stringify(result), { expirationTtl: 86400 * 7 });
    if (format === "sarif") return json(toSarif(result));
    return json(result);
  } catch (e: any) {
    return json({ error: e.message }, 500);
  }
}

async function handleScanProfile(request: Request, env: Env): Promise<Response> {
  let body: any;
  try { body = await request.json(); } catch { return json({ error: "invalid JSON body" }, 400); }

  const username = body.username;
  if (!username) return json({ error: "username is required" }, 400);

  const token = await extractToken(request, env);
  const repos = await listUserRepos(username, token);
  const results: ScanResult[] = [];
  const errors: string[] = [];

  for (const r of repos) {
    try {
      const result = await scanRepo(r.owner, r.name, token);
      await env.SCANS.put(`scan:${r.owner}:${r.name}`, JSON.stringify(result), { expirationTtl: 86400 * 7 });
      results.push(result);
    } catch (e: any) {
      errors.push(`${r.name}: ${e.message}`);
    }
  }

  await env.SCANS.put(`profile:${username}`, JSON.stringify({
    username, scannedAt: new Date().toISOString(),
    repos: results.map(r => ({ repo: r.repo, totalMatches: r.matches.length, summary: r.summary })),
    totalRepos: repos.length, scannedRepos: results.length, errorRepos: errors.length,
  }), { expirationTtl: 86400 * 7 });

  return json({ profile: username, repos: results.length, errors });
}

async function handleScanInstallations(request: Request, env: Env): Promise<Response> {
  const token = await extractToken(request, env);
  if (!token) return json({ error: "authentication required — provide a GitHub token" }, 401);

  const installations = await listAppInstallations(token);
  const allResults: Array<{ installation: string; repos: number }> = [];
  const allErrors: string[] = [];

  for (const inst of installations) {
    const repos = await listInstallationRepos(inst.id, token);
    for (const r of repos) {
      try {
        const result = await scanRepo(r.owner, r.name, token);
        await env.SCANS.put(`scan:${r.owner}:${r.name}`, JSON.stringify(result), { expirationTtl: 86400 * 7 });
      } catch (e: any) {
        allErrors.push(`${r.owner}/${r.name}: ${e.message}`);
      }
    }
    allResults.push({ installation: inst.account, repos: repos.length });
  }

  return json({ installations: allResults, totalErrors: allErrors.length, errors: allErrors.slice(0, 20) });
}

// ── Webhook ───────────────────────────────────────────────

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  // Clone body for signature verification
  const rawBody = await request.text();
  const signature = request.headers.get("x-hub-signature-256");

  // Verify signature if webhook secret is configured
  if (env.WEBHOOK_SECRET) {
    const valid = await verifyWebhookSignature(rawBody, signature, env.WEBHOOK_SECRET);
    if (!valid) return json({ error: "invalid webhook signature" }, 401);
  }

  const body = JSON.parse(rawBody);
  const event = request.headers.get("x-github-event");
  const deliveryId = request.headers.get("x-github-delivery");

  if (event === "ping") {
    return json({ message: "pong", delivery: deliveryId });
  }

  if (event !== "push") {
    return json({ message: `event "${event}" received but not processed (only 'push' is scanned)`, delivery: deliveryId });
  }

  const owner = body.repository?.owner?.name || body.repository?.owner?.login;
  const repo = body.repository?.name;
  const before = body.before;
  const after = body.after;
  const headCommit = body.head_commit?.id || after;

  if (!owner || !repo) {
    return json({ error: "invalid webhook payload" }, 400);
  }

  const token = await extractToken(request, env);

  try {
    const files = await getPushDiff(owner, repo, before, after, token);
    const allMatches: ScanMatch[] = [];
    for (const f of files) {
      if (!f.patch) continue;
      allMatches.push(...scanFile(f.path, f.patch));
    }

    const result: ScanResult = {
      repo: `${owner}/${repo}`,
      scannedAt: new Date().toISOString(),
      totalFiles: files.length,
      matches: allMatches,
      summary: summarize(allMatches),
    };

    await env.SCANS.put(`scan:${owner}:${repo}`, JSON.stringify(result), { expirationTtl: 86400 * 7 });

    // Post commit status / check run if token is available
    if (token && headCommit) {
      const severityCounts = result.summary;
      const hasBlocks = (severityCounts["secrets"] || 0) > 0
                      || (severityCounts["sensitive_files"] || 0) > 0
                      || (severityCounts["merge_conflicts"] || 0) > 0;

      const desc = `${allMatches.length} finding(s) — ${hasBlocks ? "BLOCKING issues found" : "warnings only"}`;
      const details = allMatches.length === 0
        ? "✓ No issues found in this push."
        : allMatches.map(m => `- **${m.path}** L${m.lineNumber}: ${m.pattern}: \`${m.line}\``).join("\n");

      try {
        await createCommitStatus(owner, repo, headCommit,
          hasBlocks ? "failure" : "success", desc, `${env.BASE_URL}/scan/${owner}/${repo}`, token);
        await createCheckRun(owner, repo, headCommit, "push scan",
          `${allMatches.length} finding(s)`, details, token);
      } catch {}
    }

    return json({
      status: "ok",
      delivery: deliveryId,
      matches: allMatches.length,
      summary: result.summary,
      details: allMatches.slice(0, 20),
    });
  } catch (e: any) {
    return json({ error: e.message, delivery: deliveryId }, 500);
  }
}

async function handleWebhookSetup(request: Request, env: Env): Promise<Response> {
  return html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>safepush — webhook setup</title>
<style>
  body { background:#0d1117; color:#e6edf3; font-family:system-ui; max-width:800px; margin:0 auto; padding:40px 20px; }
  h1 { color:#3fb950; } h2 { margin-top:32px; color:#58a6ff; }
  code { background:#161b22; padding:2px 8px; border-radius:4px; font-size:13px; color:#58a6ff; }
  pre { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; overflow-x:auto; }
  .step { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; margin:16px 0; }
  .step p { color:#8b949e; }
</style>
</head>
<body>
<h1>🔐 safepush — webhook setup</h1>
<p>Set up a GitHub webhook to scan every push automatically.</p>

<div class="step">
<h2>1. Go to your repo settings</h2>
<p><code>https://github.com/YOU/REPO/settings/hooks</code></p>
</div>

<div class="step">
<h2>2. Add webhook</h2>
<p><strong>Payload URL:</strong></p>
<pre>${env.BASE_URL}/webhook</pre>
<p><strong>Content type:</strong> <code>application/json</code></p>
<p><strong>Secret:</strong> same as <code>WEBHOOK_SECRET</code> env var</p>
<p><strong>Events:</strong> Just the <code>push</code> event</p>
</div>

<div class="step">
<h2>3. Test it</h2>
<pre>curl -X POST ${env.BASE_URL}/webhook \\
  -H 'x-github-event: ping' \\
  -H 'content-type: application/json' \\
  -d '{"zen":"test"}'</pre>
<p>You should get <code>{"message":"pong"}</code></p>
</div>

<div class="step">
<h2>4. Scan all repos in one go</h2>
<p>Already have a token? Scan all your repos:</p>
<pre>curl -X POST ${env.BASE_URL}/scan-installations \\
  -H 'authorization: Bearer YOUR_GITHUB_TOKEN'</pre>
</div>
</body></html>`);
}

// ── Results ───────────────────────────────────────────────

async function handleGetScan(owner: string, repo: string, env: Env): Promise<Response> {
  const data = await env.SCANS.get(`scan:${owner}:${repo}`);
  if (!data) return json({ error: "no scan found for this repo. POST /scan first." }, 404);
  return json(JSON.parse(data));
}

async function handleDashboard(owner: string, env: Env): Promise<Response> {
  const data = await env.SCANS.get(`profile:${owner}`);
  if (!data) return json({ owner, message: "No scan profile found. POST /scan-profile with {username} to start." });
  return json(JSON.parse(data));
}

// ── Tracked repos ─────────────────────────────────────────

interface TrackedRepo { owner: string; repo: string; addedAt: string; }

async function getTrackedRepos(sessionId: string, env: Env): Promise<TrackedRepo[]> {
  const raw = await env.SCANS.get(`tracked:${sessionId}`);
  return raw ? JSON.parse(raw) : [];
}

async function saveTrackedRepos(sessionId: string, repos: TrackedRepo[], env: Env): Promise<void> {
  await env.SCANS.put(`tracked:${sessionId}`, JSON.stringify(repos));
}

async function handleTrackedList(request: Request, env: Env): Promise<Response> {
  const sessionId = request.headers.get("x-safepush-session")
    || new URL(request.url).searchParams.get("session");
  if (!sessionId) return json({ error: "session required" }, 401);
  const repos = await getTrackedRepos(sessionId, env);
  return json(repos);
}

async function handleTrackedAdd(request: Request, env: Env): Promise<Response> {
  const sessionId = request.headers.get("x-safepush-session")
    || new URL(request.url).searchParams.get("session");
  if (!sessionId) return json({ error: "session required" }, 401);

  let body: any;
  try { body = await request.json(); } catch { return json({ error: "invalid JSON" }, 400); }
  const { owner, repo } = body;
  if (!owner || !repo) return json({ error: "owner and repo required" }, 400);

  const repos = await getTrackedRepos(sessionId, env);
  if (repos.some(r => r.owner === owner && r.repo === repo)) {
    return json({ error: "already tracked" }, 409);
  }
  repos.push({ owner, repo, addedAt: new Date().toISOString() });
  await saveTrackedRepos(sessionId, repos, env);
  return json({ tracked: repos.length, repos });
}

async function handleTrackedRemove(owner: string, repo: string, request: Request, env: Env): Promise<Response> {
  const sessionId = request.headers.get("x-safepush-session")
    || new URL(request.url).searchParams.get("session");
  if (!sessionId) return json({ error: "session required" }, 401);

  let repos = await getTrackedRepos(sessionId, env);
  repos = repos.filter(r => !(r.owner === owner && r.repo === repo));
  await saveTrackedRepos(sessionId, repos, env);
  return json({ tracked: repos.length, repos });
}

async function handleTrackedScan(request: Request, env: Env): Promise<Response> {
  const sessionId = request.headers.get("x-safepush-session")
    || new URL(request.url).searchParams.get("session");
  if (!sessionId) return json({ error: "session required" }, 401);

  const token = await env.SESSIONS.get(`session:${sessionId}`);
  if (!token) return json({ error: "invalid session" }, 401);

  const repos = await getTrackedRepos(sessionId, env);
  const results: any[] = [];
  const errors: string[] = [];

  for (const r of repos) {
    try {
      const result = await scanRepo(r.owner, r.repo, token);
      await env.SCANS.put(`scan:${r.owner}:${r.repo}`, JSON.stringify(result), { expirationTtl: 86400 * 7 });
      results.push({ repo: `${r.owner}/${r.repo}`, matches: result.matches.length, summary: result.summary });
    } catch (e: any) {
      errors.push(`${r.owner}/${r.repo}: ${e.message}`);
    }
  }

  return json({ scanned: results.length, errors: errors.length, results, errorList: errors.slice(0, 20) });
}

// ── My repos (for picker) ──────────────────────────────────

async function handleMyRepos(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionCookie(request)
    || request.headers.get("x-safepush-session");
  if (!sessionId) return json({ error: "session required" }, 401);

  const token = await env.SESSIONS.get(`session:${sessionId}`);
  if (!token) return json({ error: "invalid session" }, 401);

  const username = await env.SESSIONS.get(`user:${sessionId}`);
  if (!username) return json({ error: "user not found" }, 401);

  const repos = await listUserRepos(username, token);
  return json(repos);
}

// ── Dashboard UI ───────────────────────────────────────────

function getSessionCookie(request: Request): string {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/safepush_session=([^;]+)/);
  return match ? match[1] : "";
}

async function handleDashboardUI(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionCookie(request)
    || new URL(request.url).searchParams.get("session")
    || request.headers.get("x-safepush-session") || "";

  const token = sessionId ? await env.SESSIONS.get(`session:${sessionId}`) : null;
  const username = token ? await env.SESSIONS.get(`user:${sessionId}`) : null;
  const repos = sessionId ? await getTrackedRepos(sessionId, env) : [];

  const repoRows = repos.length === 0
    ? `<tr><td colspan="4" style="color:#8b949e;text-align:center;padding:32px">No repos tracked yet. Add one below or load your repos.</td></tr>`
    : repos.map(r => `
      <tr>
        <td style="font-family:monospace">${r.owner}/${r.repo}</td>
        <td style="color:#8b949e;font-size:12px">${r.addedAt.slice(0,10)}</td>
        <td><a href="/scan/${r.owner}/${r.repo}" style="color:#58a6ff">view</a></td>
        <td><button onclick="removeRepoBtn('${r.owner}','${r.repo}')" style="background:none;border:none;color:#f85149;cursor:pointer;font-size:16px">&times;</button></td>
      </tr>`).join("");

  return html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>safepush — dashboard</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#0d1117; color:#e6edf3; font-family:system-ui; min-height:100vh; }
  .nav { background:#161b22; border-bottom:1px solid #30363d; padding:12px 24px; display:flex; align-items:center; justify-content:space-between; }
  .nav h2 { color:#3fb950; font-size:16px; }
  .nav-right { display:flex; align-items:center; gap:16px; }
  .nav .user { color:#8b949e; font-size:14px; }
  .nav a { color:#58a6ff; text-decoration:none; font-size:14px; }
  .nav a:hover { text-decoration:underline; }
  .container { max-width:900px; margin:0 auto; padding:32px 24px; }
  h1 { font-size:24px; margin-bottom:8px; }
  .add-form { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; margin-bottom:24px; display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end; }
  .add-form input { background:#0d1117; border:1px solid #30363d; color:#e6edf3; padding:10px 14px; border-radius:6px; font-size:14px; }
  .add-form input:focus { outline:none; border-color:#58a6ff; }
  .btn { padding:10px 20px; border-radius:6px; font-weight:600; font-size:14px; cursor:pointer; border:none; transition:background .15s; }
  .btn-green { background:#3fb950; color:#000; }
  .btn-green:hover { background:#2ea043; }
  .btn-blue { background:#1f6feb; color:#fff; }
  .btn-blue:hover { background:#1158c7; }
  .btn-outline { background:transparent; border:1px solid #30363d; color:#e6edf3; }
  .btn-outline:hover { background:#21262d; }
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:10px 14px; color:#8b949e; font-size:12px; text-transform:uppercase; border-bottom:1px solid #30363d; }
  td { padding:10px 14px; border-bottom:1px solid #21262d; font-size:14px; }
  .scan-results { margin-top:24px; background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; display:none; }
  .scan-results h3 { color:#3fb950; margin-bottom:12px; }
  .result-item { padding:8px 0; border-bottom:1px solid #21262d; font-size:13px; }
  .result-item:last-child { border-bottom:none; }
  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; margin-right:6px; }
  .badge-danger { background:rgba(248,81,73,0.2); color:#f85149; }
  .badge-warn { background:rgba(210,153,34,0.2); color:#d29922; }
  .badge-ok { background:rgba(63,185,80,0.2); color:#3fb950; }
  #status { margin-left:12px; font-size:13px; color:#8b949e; }
  .picker-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:8px; margin-bottom:24px; }
  .picker-item { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:10px 14px; cursor:pointer; font-size:13px; font-family:monospace; display:flex; justify-content:space-between; align-items:center; transition:border-color .15s; }
  .picker-item:hover { border-color:#58a6ff; }
  .picker-item .add-icon { color:#3fb950; font-weight:bold; font-size:18px; display:none; }
  .picker-item:hover .add-icon { display:inline; }
  .picker-item.added { border-color:#3fb950; opacity:0.5; cursor:default; }
  .picker-item.added .add-icon { display:inline; color:#3fb950; }
  .section-title { font-size:14px; color:#8b949e; text-transform:uppercase; letter-spacing:0.05em; margin-bottom:12px; display:flex; align-items:center; gap:12px; }
  .section-title .count { color:#58a6ff; }
</style>
</head>
<body>
<div class="nav">
  <h2>🔐 safepush</h2>
  <div class="nav-right">
    <span class="user">${username ? `👤 ${username}` : 'not logged in'}</span>
    ${sessionId ? '<a href="/logout">Logout</a>' : '<a href="/login">Login</a>'}
  </div>
</div>
<div class="container">
  ${!sessionId ? `<div style="text-align:center;padding:80px 0">
    <h1>safepush</h1>
    <p style="color:#8b949e;margin:16px 0 32px">Track and scan your GitHub repos for secrets, debug prints, and more.</p>
    <a href="/login" class="btn btn-green" style="display:inline-block;text-decoration:none;font-size:16px;padding:14px 36px">🔑 Login with GitHub</a>
  </div>` : `
  <h1>📋 Tracked Repos</h1>

  <div class="section-title" style="margin-top:24px"><span>🔍 Load your repos</span></div>
  <div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center">
    <input id="repo-owner" placeholder="GitHub username or org" value="${username}" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:10px 14px;border-radius:6px;font-size:14px;width:240px">
    <button class="btn btn-outline" onclick="loadRepos()" id="btn-load">Load Repos</button>
    <button class="btn btn-blue" onclick="trackAll()">+ Track All</button>
    <span id="load-status" style="font-size:13px;color:#8b949e"></span>
  </div>
  <div class="picker-grid" id="repo-picker"></div>

  <div class="section-title"><span>📌 Tracked (${repos.length})</span></div>
  <div class="add-form">
    <input id="owner" placeholder="owner" value="${username}" style="flex:1;min-width:140px">
    <input id="repo" placeholder="repo name" style="flex:1;min-width:140px">
    <button class="btn btn-green" onclick="addRepoBtn()">+ Add</button>
  </div>

  <table>
    <thead><tr><th>Repository</th><th>Added</th><th>Results</th><th></th></tr></thead>
    <tbody id="repo-list">${repoRows}</tbody>
  </table>

  <div style="margin-top:24px;display:flex;align-items:center;gap:12px">
    <button class="btn btn-blue" onclick="scanAll()">🔍 Scan All Tracked</button>
    <span id="status"></span>
  </div>

  <div class="scan-results" id="scan-results">
    <h3>Scan Results</h3>
    <div id="results-body"></div>
  </div>`}
</div>

<script>
var SESSION = "${sessionId}";
var BASE = "${env.BASE_URL || `https://${new URL(request.url).host}`}";
var trackedSet = {};
${repos.map(r => 'trackedSet["' + r.owner + '/' + r.repo + '"]=1;').join('\n')}

function api(method, path, body) {
  var opts = {method:method,headers:{'content-type':'application/json','x-safepush-session':SESSION},credentials:'same-origin'};
  if(body) opts.body = JSON.stringify(body);
  return fetch(BASE+path,opts).then(function(r){return r.json();}).then(function(d){if(d.error)throw new Error(d.error);return d;});
}

function addRepoBtn() {
  var o=document.getElementById('owner').value.trim(), r=document.getElementById('repo').value.trim();
  if(!o||!r){alert('Fill both fields');return;}
  api('POST','/tracked',{owner:o,repo:r}).then(function(){location.reload();}).catch(function(e){alert(e.message);});
}

function removeRepoBtn(owner,repo) {
  api('DELETE','/tracked/'+owner+'/'+repo).then(function(){location.reload();});
}

function scanAll() {
  var tds=document.querySelectorAll('#repo-list td:first-child'), items=[];
  tds.forEach(function(t){var p=t.textContent.trim().split('/');if(p.length===2)items.push({o:p[0],r:p[1]});});
  var stat=document.getElementById('status'), box=document.getElementById('results-body');
  document.getElementById('scan-results').style.display='block';
  var html='', ok=0, fail=0;

  function next(i) {
    if(i>=items.length){stat.textContent='Done: '+ok+' scanned'+(fail?', '+fail+' failed':'');return;}
    var it=items[i];
    stat.textContent='Scanning '+(i+1)+'/'+items.length+': '+it.o+'/'+it.r+'...';
    api('POST','/scan',{owner:it.o,repo:it.r}).then(function(res){
      var r=res.repo?res:{repo:it.o+'/'+it.r,matches:[],summary:{}};
      var bl=(r.summary.secrets||0)+(r.summary.sensitive_files||0)+(r.summary.merge_conflicts||0);
      var wn=(r.summary.debug_prints||0)+(r.summary.hardcoded_connections||0);
      var b=bl>0?'<span class="badge badge-danger">BLOCK</span>':wn>0?'<span class="badge badge-warn">WARN</span>':'<span class="badge badge-ok">CLEAN</span>';
      var n=r.matches?r.matches.length:0;
      html+='<div class="result-item" onclick="toggleDetails(this)" style="cursor:pointer">'+b+'<strong>'+r.repo+'</strong> \\u2014 '+n+' finding(s) <span style="color:#484f58;font-size:11px">\\u25b8</span></div>';
      if(r.matches&&r.matches.length>0){
        html+='<div class="match-details" style="display:none;background:#0d1117;border-radius:0 0 6px 6px;margin:-1px 0 4px 0">';
        for(var j=0,mx=Math.min(r.matches.length,50);j<mx;j++){var m=r.matches[j],ic=m.severity==='BLOCK'?'\\ud83d\\udd34':m.severity==='WARN'?'\\ud83d\\udfe1':'\\ud83d\\udd35';
          html+='<div style="padding:4px 0 4px 16px;font-size:12px;color:#8b949e">'+ic+' <code style="color:#58a6ff;font-size:11px">'+m.path+':'+(m.lineNumber||'?')+'</code> <span style="color:#e6edf3">'+m.pattern+'</span><span style="color:#484f58;margin-left:8px">'+(m.line||'').slice(0,80)+'</span></div>';}
        if(r.matches.length>50)html+='<div style="padding:4px 16px;font-size:12px;color:#8b949e">... and '+(r.matches.length-50)+' more</div>';
        html+='</div>';
      }
      ok++;box.innerHTML=html;next(i+1);
    }).catch(function(){html+='<div class="result-item" style="color:#f85149">\\u274c <strong>'+it.o+'/'+it.r+'</strong> \\u2014 failed</div>';fail++;box.innerHTML=html;next(i+1);});
  }
  next(0);
}

function toggleDetails(el){var n=el.nextElementSibling;if(n&&n.className==='match-details')n.style.display=n.style.display==='none'?'':'none';}

function loadRepos(){
  var o=document.getElementById('repo-owner').value.trim();
  if(!o)return;
  var s=document.getElementById('load-status'),g=document.getElementById('repo-picker');
  s.textContent='Loading...';g.innerHTML='';
  api('GET','/my-repos').then(function(repos){
    s.textContent=repos.length+' repos found';
    repos.forEach(function(r){var k=r.owner+'/'+r.name,d=document.createElement('div');d.className='picker-item'+(trackedSet[k]?' added':'');d.innerHTML='<span>'+k+'</span><span class="add-icon">'+(trackedSet[k]?'\\u2713':'+')+'</span>';if(!trackedSet[k])d.onclick=function(){trackRepo(r.owner,r.name,d);};g.appendChild(d);});
  }).catch(function(e){s.textContent='Error: '+(e.message||'failed');});
}

function trackRepo(owner,repo,el){api('POST','/tracked',{owner:owner,repo:repo}).then(function(){el.classList.add('added');el.querySelector('.add-icon').textContent='\\u2713';el.onclick=null;trackedSet[owner+'/'+repo]=1;}).catch(function(e){alert(e.message);});}

function trackAll(){
  var its=document.querySelectorAll('.picker-item:not(.added)');
  if(!its.length)return;
  var s=document.getElementById('load-status'),t=its.length,c=0;
  var arr=[];its.forEach(function(el){var p=el.querySelector('span').textContent.split('/');if(p.length===2)arr.push({el:el,o:p[0],r:p[1]});});
  s.textContent='Adding '+arr.length+' repos...';
  function next(i){if(i>=arr.length){s.textContent=c+' added';setTimeout(function(){location.reload();},500);return;}var it=arr[i];s.textContent='Adding '+(i+1)+'/'+arr.length+': '+it.o+'/'+it.r+'...';api('POST','/tracked',{owner:it.o,repo:it.r}).then(function(){it.el.classList.add('added');it.el.querySelector('.add-icon').textContent='\\u2713';it.el.onclick=null;trackedSet[it.o+'/'+it.r]=1;c++;next(i+1);}).catch(function(){next(i+1);});}
  next(0);
}
</script>

</body></html>`);
}

// ── Landing page ──────────────────────────────────────────

async function handleLanding(env: Env): Promise<Response> {
  const hasOAuth = !!(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);
  const loginBlock = hasOAuth
    ? `<a href="/login" style="display:inline-block;background:#3fb950;color:#000;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:16px">🔑 Login with GitHub</a>`
    : `<p style="color:#d29922">⚠ OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.</p>`;

  return html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>safepush — cloud scanner</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#0d1117; color:#e6edf3; font-family:system-ui; min-height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:12px; padding:48px; max-width:680px; text-align:center; }
  h1 { font-size:2rem; margin-bottom:8px; }
  h1 span { color:#3fb950; }
  .sub { color:#8b949e; margin-bottom:28px; }
  .auth-box { margin:24px 0; padding:20px; background:#0d1117; border-radius:8px; }
  .section { text-align:left; margin:24px 0; }
  .section h3 { color:#58a6ff; margin-bottom:8px; font-size:14px; text-transform:uppercase; letter-spacing:0.05em; }
  code { background:#0d1117; padding:10px 16px; border-radius:6px; font-size:13px; color:#3fb950; display:block; margin:8px 0; text-align:left; word-break:break-all; }
  .tag { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; margin-right:4px; }
  .tag-green { background:rgba(63,185,80,0.2); color:#3fb950; }
  .tag-blue { background:rgba(88,166,255,0.2); color:#58a6ff; }
  .tag-yellow { background:rgba(210,153,34,0.2); color:#d29922; }
</style>
</head>
<body>
<div class="card">
  <h1>safepush <span>cloud scanner</span></h1>
  <p class="sub">Scan GitHub repos for secrets, API keys, debug prints — continuously.</p>

  <div class="auth-box">${loginBlock}</div>

  <div class="section">
    <h3><span class="tag tag-green">POST</span> Scan a repo</h3>
    <code>curl -X POST ${env.BASE_URL}/scan -H 'content-type: application/json' -d '{"owner":"user","repo":"repo"}'</code>
  </div>
  <div class="section">
    <h3><span class="tag tag-green">POST</span> Scan entire profile</h3>
    <code>curl -X POST ${env.BASE_URL}/scan-profile -H 'content-type: application/json' -d '{"username":"github-user"}'</code>
  </div>
  <div class="section">
    <h3><span class="tag tag-yellow">POST</span> Webhook (CI)</h3>
    <code>curl -X POST ${env.BASE_URL}/webhook -H 'x-github-event: push' -H 'content-type: application/json' -d @payload.json</code>
  </div>
  <div class="section">
    <h3><span class="tag tag-blue">GET</span> View results</h3>
    <code>curl ${env.BASE_URL}/dashboard/:user</code>
    <code>curl ${env.BASE_URL}/scan/:owner/:repo</code>
  </div>
  <p style="color:#8b949e; font-size:13px; margin-top:24px">
    Add <code style="display:inline;padding:2px 6px;font-size:12px">-H 'x-github-token: ghp_xxx'</code> for private repos &nbsp;|&nbsp;
    <a href="/webhook/setup" style="color:#58a6ff">webhook setup guide</a>
  </p>
</div>
</body></html>`);
}

// ── Main ──────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors(request) });
    }

    const c = cors(request);

    try {
      // Auth
      if (method === "GET" && path === "/login")         return handleLogin(request, env);
      if (method === "GET" && path === "/callback")      return handleCallback(request, env);
      if (method === "GET" && path === "/logout")        return handleLogout();
      if (method === "GET" && path === "/auth/status")   return handleAuthStatus(request, env);

      // Scanning
      if (method === "POST" && path === "/scan")                { const r = await handleScan(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }
      if (method === "POST" && path === "/scan-profile")        { const r = await handleScanProfile(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }
      if (method === "POST" && path === "/scan-installations")  { const r = await handleScanInstallations(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }

      // Webhook
      if (method === "POST" && path === "/webhook")       { const r = await handleWebhook(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }
      if (method === "GET"  && path === "/webhook/setup") return handleWebhookSetup(request, env);

      // Results
      const scanMatch = path.match(/^\/scan\/([^/]+)\/([^/]+)$/);
      if (method === "GET" && scanMatch) { const r = await handleGetScan(scanMatch[1], scanMatch[2], env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }

      const dashMatch = path.match(/^\/dashboard\/([^/]+)$/);
      if (method === "GET" && dashMatch) { const r = await handleDashboard(dashMatch[1], env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }

      // Tracked repos
      if (method === "GET"  && path === "/tracked")            { const r = await handleTrackedList(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }
      if (method === "POST" && path === "/tracked")            { const r = await handleTrackedAdd(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }
      if (method === "GET"  && path === "/tracked/scan")       { const r = await handleTrackedScan(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }
      if (method === "GET"  && path === "/my-repos")           { const r = await handleMyRepos(request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }
      const trackedRemoveMatch = path.match(/^\/tracked\/([^/]+)\/([^/]+)$/);
      if (method === "DELETE" && trackedRemoveMatch) { const r = await handleTrackedRemove(trackedRemoveMatch[1], trackedRemoveMatch[2], request, env); Object.entries(c).forEach(([k,v]) => r.headers.set(k,v)); return r; }

      // Dashboard UI (also at /app for backwards compat)
      if (method === "GET" && (path === "/" || path === "/app")) return handleDashboardUI(request, env);

      return json({ error: "not found" }, 404);
    } catch (e: any) {
      return json({ error: e.message || "internal error" }, 500);
    }
  },
};
