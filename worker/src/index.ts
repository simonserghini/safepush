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
  const sessionId = request.headers.get("x-safepush-session");
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

  // Return HTML page that stores the session and redirects
  return html(`<!DOCTYPE html>
<html>
<head><title>safepush — logged in</title>
<style>
  body { background:#0d1117; color:#e6edf3; font-family:system-ui; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:12px; padding:48px; text-align:center; }
  h1 { color:#3fb950; }
  code { background:#0d1117; padding:4px 10px; border-radius:4px; font-size:14px; color:#58a6ff; }
</style></head>
<body>
<div class="card">
  <h1>✓ Logged in as ${username}</h1>
  <p>Your session token:</p>
  <code>${sessionId}</code>
  <p style="margin-top:16px;color:#8b949e">Use this in your requests:</p>
  <code>curl -H 'x-safepush-session: ${sessionId}' https://${url.host}/scan -d '{"owner":"...","repo":"..."}'</code>
  <p style="margin-top:24px"><a href="/" style="color:#58a6ff">← back home</a></p>
</div>
</body></html>`);
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
      if (content) allMatches.push(...scanFile(f.path, content));
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

  try {
    const result = await scanRepo(owner, repo, token);
    await env.SCANS.put(`scan:${owner}:${repo}`, JSON.stringify(result), { expirationTtl: 86400 * 7 });
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

      // Landing
      if (method === "GET" && path === "/") return handleLanding(env);

      return json({ error: "not found" }, 404);
    } catch (e: any) {
      return json({ error: e.message || "internal error" }, 500);
    }
  },
};
