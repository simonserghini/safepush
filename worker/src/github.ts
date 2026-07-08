/**
 * GitHub API client for safepush cloud scanner.
 * Handles repo fetching, file listing, content retrieval,
 * webhook verification, and PR commenting.
 */

export interface RepoInfo {
  owner: string;
  repo: string;
  defaultBranch: string;
}

export interface RepoFile {
  path: string;
  type: "file" | "dir";
  size: number;
}

const GITHUB_API = "https://api.github.com";

function headers(token?: string): Record<string, string> {
  const h: Record<string, string> = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "safepush-cloud-scanner",
  };
  if (token) h["Authorization"] = `Bearer ${token}`;
  return h;
}

// ── Webhook signature verification (HMAC-SHA256) ──────────

export async function verifyWebhookSignature(
  body: string,
  signature: string | null,
  secret: string
): Promise<boolean> {
  if (!signature || !secret) return false;
  const expected = signature.replace(/^sha256=/, "");

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sigBytes = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  const actual = Array.from(new Uint8Array(sigBytes))
    .map(b => b.toString(16).padStart(2, "0")).join("");

  // Constant-time-ish comparison
  if (expected.length !== actual.length) return false;
  let ok = 0;
  for (let i = 0; i < expected.length; i++) {
    ok |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  }
  return ok === 0;
}

// ── OAuth ──────────────────────────────────────────────────

const GITHUB_OAUTH = "https://github.com/login/oauth";

export function getOAuthURL(clientId: string, redirectUri: string, state: string): string {
  return `${GITHUB_OAUTH}/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}&scope=repo,read:user`;
}

export async function exchangeOAuthCode(
  code: string,
  clientId: string,
  clientSecret: string
): Promise<string | null> {
  const resp = await fetch(`${GITHUB_OAUTH}/access_token`, {
    method: "POST",
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "User-Agent": "safepush-cloud-scanner",
    },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
  });
  if (!resp.ok) return null;
  const data = await resp.json() as any;
  return data.access_token || null;
}

export async function getOAuthUser(token: string): Promise<string | null> {
  const resp = await fetch(`${GITHUB_API}/user`, { headers: headers(token) });
  if (!resp.ok) return null;
  const data = await resp.json() as any;
  return data.login || null;
}

// ── Repo operations ────────────────────────────────────────

export async function getRepoInfo(
  owner: string, repo: string, token?: string
): Promise<RepoInfo | null> {
  const resp = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers: headers(token) });
  if (!resp.ok) return null;
  const data = await resp.json() as any;
  return { owner: data.owner.login, repo: data.name, defaultBranch: data.default_branch };
}

export async function listRepoFiles(
  owner: string, repo: string, branch: string, token?: string
): Promise<RepoFile[]> {
  const branchResp = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/git/ref/heads/${branch}`,
    { headers: headers(token) }
  );
  if (!branchResp.ok) return [];
  const branchData = await branchResp.json() as any;
  const commitSha: string = branchData.object.sha;

  const treeResp = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/git/trees/${commitSha}?recursive=1`,
    { headers: headers(token) }
  );
  if (!treeResp.ok) return [];
  const treeData = await treeResp.json() as any;

  const files: RepoFile[] = [];
  for (const entry of (treeData.tree || [])) {
    if (entry.type === "blob") {
      files.push({ path: entry.path, type: "file", size: entry.size || 0 });
    }
  }
  return files;
}

export async function getFileContent(
  owner: string, repo: string, path: string, branch: string, token?: string
): Promise<string | null> {
  const resp = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`,
    { headers: headers(token) }
  );
  if (!resp.ok) return null;
  const data = await resp.json() as any;
  if (!data.content) return null;
  // Use TextDecoder for proper UTF-8 — atob only handles Latin-1
  const raw = atob(data.content.replace(/\n/g, ""));
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return new TextDecoder("utf-8").decode(bytes);
}

export async function listUserRepos(
  username: string, token?: string
): Promise<Array<{ name: string; owner: string }>> {
  const repos: Array<{ name: string; owner: string }> = [];
  let page = 1;
  while (true) {
    const resp = await fetch(
      `${GITHUB_API}/users/${username}/repos?per_page=100&page=${page}&sort=updated`,
      { headers: headers(token) }
    );
    if (!resp.ok) break;
    const data = await resp.json() as any[];
    if (data.length === 0) break;
    for (const r of data) repos.push({ name: r.name, owner: r.owner.login });
    page++;
    if (page > 10) break;
  }
  return repos;
}

export async function getPushDiff(
  owner: string, repo: string, before: string, after: string, token?: string
): Promise<Array<{ path: string; patch: string }>> {
  const resp = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/compare/${before}...${after}`,
    { headers: headers(token) }
  );
  if (!resp.ok) return [];
  const data = await resp.json() as any;
  const files: Array<{ path: string; patch: string }> = [];
  for (const f of (data.files || [])) {
    files.push({ path: f.filename, patch: f.patch || "" });
  }
  return files;
}

// ── Repository installation listing (for GitHub App) ──────

export async function listAppInstallations(
  token: string
): Promise<Array<{ id: number; account: string; type: string }>> {
  const resp = await fetch(`${GITHUB_API}/user/installations?per_page=100`, {
    headers: headers(token),
  });
  if (!resp.ok) return [];
  const data = await resp.json() as any;
  const installations = data.installations || [];
  return installations.map((i: any) => ({
    id: i.id,
    account: i.account?.login || "",
    type: i.account?.type || "",
  }));
}

export async function listInstallationRepos(
  installationId: number, token: string
): Promise<Array<{ name: string; owner: string; private: boolean }>> {
  const resp = await fetch(
    `${GITHUB_API}/user/installations/${installationId}/repositories?per_page=100`,
    { headers: headers(token) }
  );
  if (!resp.ok) return [];
  const data = await resp.json() as any;
  return (data.repositories || []).map((r: any) => ({
    name: r.name,
    owner: r.owner.login,
    private: r.private,
  }));
}

// ── PR commenting ──────────────────────────────────────────

export async function createCommitStatus(
  owner: string, repo: string, sha: string,
  state: "pending" | "success" | "failure",
  description: string, targetUrl: string, token: string
): Promise<void> {
  await fetch(`${GITHUB_API}/repos/${owner}/${repo}/statuses/${sha}`, {
    method: "POST",
    headers: headers(token),
    body: JSON.stringify({
      state,
      description,
      target_url: targetUrl,
      context: "safepush",
    }),
  });
}

export async function createCheckRun(
  owner: string, repo: string, headSha: string,
  name: string, summary: string, details: string, token: string
): Promise<void> {
  const resp = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/check-runs`, {
    method: "POST",
    headers: { ...headers(token), "Accept": "application/vnd.github.v3+json" },
    body: JSON.stringify({
      name: `safepush: ${name}`,
      head_sha: headSha,
      status: "completed",
      conclusion: "neutral",
      completed_at: new Date().toISOString(),
      output: {
        title: summary,
        summary: details,
      },
    }),
  });
  // Ignore errors — checks API may not be available
}
