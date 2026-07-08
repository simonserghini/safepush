/**
 * safepush Cloudflare Worker — cloud secret scanner.
 *
 * Endpoints:
 *   POST /scan          — Scan a repo (public or with token)
 *   POST /webhook       — GitHub push webhook receiver
 *   POST /scan-profile  — Scan all public repos for a GitHub user
 *   GET  /dashboard/:owner — Show scan results dashboard
 *   GET  /scan/:owner/:repo — Show results for a single repo
 *   GET  /              — Landing page
 */

import { scanFile, summarize, ScanResult } from "./scanner";
import {
  getRepoInfo,
  listRepoFiles,
  getFileContent,
  listUserRepos,
  getPushDiff,
} from "./github";

export interface Env {
  SCANS: KVNamespace;
  DASHBOARD_TITLE: string;
}

async function json(body: any, status = 200): Promise<Response> {
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
    "access-control-allow-headers": "content-type, authorization, x-github-token",
  };
}

/** Scan a full repository. */
async function scanRepo(
  owner: string,
  repo: string,
  token?: string
): Promise<ScanResult> {
  const info = await getRepoInfo(owner, repo, token);
  if (!info) throw new Error(`Repo ${owner}/${repo} not found or access denied`);

  const files = await listRepoFiles(owner, repo, info.defaultBranch, token);
  const allMatches: ScanResult["matches"] = [];

  // Scan files in batches (max 500 files to stay within Worker limits)
  const maxFiles = Math.min(files.length, 500);
  for (let i = 0; i < maxFiles; i++) {
    const f = files[i];
    // Skip binary files, node_modules, dist, etc.
    if (f.size > 1_000_000) continue; // skip files > 1MB
    const ext = f.path.split(".").pop()?.toLowerCase() || "";
    const skipDirs = ["node_modules/", "dist/", "build/", ".git/", "target/",
                      "__pycache__/", ".next/", "vendor/", "bower_components/"];
    if (skipDirs.some((d) => f.path.startsWith(d))) continue;

    try {
      const content = await getFileContent(owner, repo, f.path, info.defaultBranch, token);
      if (content) {
        const matches = scanFile(f.path, content);
        allMatches.push(...matches);
      }
    } catch {
      // Skip files we can't read
    }
  }

  const result: ScanResult = {
    repo: `${owner}/${repo}`,
    scannedAt: new Date().toISOString(),
    totalFiles: maxFiles,
    matches: allMatches,
    summary: summarize(allMatches),
  };

  // Store in KV
  return result;
}

async function handleScanProfile(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await request.json() as any;
  const username = body.username;
  const token = body.token || request.headers.get("x-github-token") || undefined;

  if (!username) {
    return json({ error: "username is required" }, 400);
  }

  const repos = await listUserRepos(username, token);
  const results: ScanResult[] = [];
  const errors: string[] = [];

  for (const r of repos) {
    try {
      const result = await scanRepo(r.owner, r.name, token);
      await env.SCANS.put(
        `scan:${r.owner}:${r.name}`,
        JSON.stringify(result),
        { expirationTtl: 86400 * 7 } // 7 days
      );
      results.push(result);
    } catch (e: any) {
      errors.push(`${r.name}: ${e.message}`);
    }
  }

  // Store profile summary
  await env.SCANS.put(
    `profile:${username}`,
    JSON.stringify({
      username,
      scannedAt: new Date().toISOString(),
      repos: results.map((r) => ({
        repo: r.repo,
        totalMatches: r.matches.length,
        summary: r.summary,
      })),
      totalRepos: repos.length,
      scannedRepos: results.length,
      errorRepos: errors.length,
    }),
    { expirationTtl: 86400 * 7 }
  );

  return json({ profile: username, repos: results.length, errors });
}

async function handleScan(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const { owner, repo, token: bodyToken } = body;
  const token = bodyToken || request.headers.get("x-github-token") || undefined;

  if (!owner || !repo) {
    return json({ error: "owner and repo are required" }, 400);
  }

  try {
    const result = await scanRepo(owner, repo, token);
    await env.SCANS.put(
      `scan:${owner}:${repo}`,
      JSON.stringify(result),
      { expirationTtl: 86400 * 7 }
    );
    return json(result);
  } catch (e: any) {
    return json({ error: e.message }, 500);
  }
}

async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const body = await request.json() as any;
  const event = request.headers.get("x-github-event");

  // Only handle push events
  if (event !== "push") {
    return json({ message: `event ${event} ignored` });
  }

  const owner = body.repository?.owner?.name || body.repository?.owner?.login;
  const repo = body.repository?.name;
  const before = body.before;
  const after = body.after;
  const token = request.headers.get("x-github-token") || undefined;

  if (!owner || !repo) {
    return json({ error: "invalid webhook payload" }, 400);
  }

  try {
    const files = await getPushDiff(owner, repo, before, after, token);
    const allMatches: ScanResult["matches"] = [];

    for (const f of files) {
      if (!f.patch) continue;
      const matches = scanFile(f.path, f.patch);
      allMatches.push(...matches);
    }

    const result: ScanResult = {
      repo: `${owner}/${repo}`,
      scannedAt: new Date().toISOString(),
      totalFiles: files.length,
      matches: allMatches,
      summary: summarize(allMatches),
    };

    await env.SCANS.put(
      `scan:${owner}:${repo}`,
      JSON.stringify(result),
      { expirationTtl: 86400 * 7 }
    );

    return json({ status: "ok", matches: allMatches.length, summary: result.summary });
  } catch (e: any) {
    return json({ error: e.message }, 500);
  }
}

async function handleGetScan(owner: string, repo: string, env: Env): Promise<Response> {
  const data = await env.SCANS.get(`scan:${owner}:${repo}`);
  if (!data) return json({ error: "no scan found for this repo" }, 404);
  return json(JSON.parse(data));
}

async function handleDashboard(owner: string, env: Env): Promise<Response> {
  const data = await env.SCANS.get(`profile:${owner}`);
  if (!data) {
    return json({
      owner,
      message: "No scan profile found. POST /scan-profile with { username } to start.",
    });
  }
  return json(JSON.parse(data));
}

async function handleLanding(): Promise<Response> {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>safepush — cloud scanner</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #e6edf3; font-family: system-ui, sans-serif; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 48px; max-width: 600px; text-align: center; }
  h1 { font-size: 2rem; margin-bottom: 12px; }
  h1 span { color: #3fb950; }
  p { color: #8b949e; margin-bottom: 32px; line-height: 1.6; }
  code { background: #0d1117; padding: 12px 20px; border-radius: 8px; font-size: 14px; color: #58a6ff; display: block; margin: 12px 0; text-align: left; word-break: break-all; }
  .endpoint { margin: 20px 0; }
  .method { display: inline-block; background: #3fb950; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 700; margin-right: 8px; }
  .path { font-family: monospace; color: #e6edf3; }
  a { color: #58a6ff; }
</style>
</head>
<body>
<div class="card">
  <h1>safepush <span>cloud scanner</span></h1>
  <p>Scan any GitHub repo or entire profile for secrets, API keys, debug prints, and more — all running on Cloudflare Workers.</p>

  <div class="endpoint">
    <span class="method">POST</span><span class="path">/scan</span>
    <code>curl -X POST ${"{{baseURL}}".replace("{{baseURL}}", "")}/scan -H 'content-type: application/json' -d '{"owner":"user","repo":"repo"}'</code>
  </div>
  <div class="endpoint">
    <span class="method">POST</span><span class="path">/scan-profile</span>
    <code>curl -X POST ${"{{baseURL}}".replace("{{baseURL}}", "")}/scan-profile -H 'content-type: application/json' -d '{"username":"github-user"}'</code>
  </div>
  <div class="endpoint">
    <span class="method">GET</span><span class="path">/dashboard/:user</span>
    <p style="margin-top:8px">View scan results for an entire profile</p>
  </div>
  <p style="margin-top:24px; font-size:13px">Supply a GitHub token via <code>x-github-token</code> header to scan private repos.</p>
</div>
</body>
</html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8", ...cors(new Request("http://localhost")) },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors(request) });
    }

    const c = cors(request);

    try {
      // POST /scan
      if (method === "POST" && path === "/scan") {
        const resp = await handleScan(request, env);
        Object.entries(c).forEach(([k, v]) => resp.headers.set(k, v));
        return resp;
      }

      // POST /scan-profile
      if (method === "POST" && path === "/scan-profile") {
        const resp = await handleScanProfile(request, env);
        Object.entries(c).forEach(([k, v]) => resp.headers.set(k, v));
        return resp;
      }

      // POST /webhook
      if (method === "POST" && path === "/webhook") {
        const resp = await handleWebhook(request, env);
        Object.entries(c).forEach(([k, v]) => resp.headers.set(k, v));
        return resp;
      }

      // GET /scan/:owner/:repo
      const scanMatch = path.match(/^\/scan\/([^\/]+)\/([^\/]+)$/);
      if (method === "GET" && scanMatch) {
        const resp = await handleGetScan(scanMatch[1], scanMatch[2], env);
        Object.entries(c).forEach(([k, v]) => resp.headers.set(k, v));
        return resp;
      }

      // GET /dashboard/:owner
      const dashMatch = path.match(/^\/dashboard\/([^\/]+)$/);
      if (method === "GET" && dashMatch) {
        const resp = await handleDashboard(dashMatch[1], env);
        Object.entries(c).forEach(([k, v]) => resp.headers.set(k, v));
        return resp;
      }

      // GET /
      if (method === "GET" && path === "/") {
        return handleLanding();
      }

      return json({ error: "not found", endpoints: ["POST /scan", "POST /scan-profile", "POST /webhook", "GET /dashboard/:user", "GET /scan/:owner/:repo"] }, 404);
    } catch (e: any) {
      return json({ error: e.message || "internal error" }, 500);
    }
  },
};
