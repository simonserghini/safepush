/**
 * GitHub API client for safepush cloud scanner.
 * Handles repo fetching, file listing, and content retrieval.
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

/** Fetch a repo's default branch and basic info. */
export async function getRepoInfo(
  owner: string,
  repo: string,
  token?: string
): Promise<RepoInfo | null> {
  const resp = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers: headers(token) });
  if (!resp.ok) return null;
  const data = await resp.json() as any;
  return {
    owner: data.owner.login,
    repo: data.name,
    defaultBranch: data.default_branch,
  };
}

/** List all files in a repo (recursively from git trees). */
export async function listRepoFiles(
  owner: string,
  repo: string,
  branch: string,
  token?: string
): Promise<RepoFile[]> {
  // Get the latest commit SHA on the branch
  const branchResp = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/git/ref/heads/${branch}`,
    { headers: headers(token) }
  );
  if (!branchResp.ok) return [];
  const branchData = await branchResp.json() as any;
  const commitSha: string = branchData.object.sha;

  // Get the tree recursively
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

/** Fetch a single file's content (base64-decoded). */
export async function getFileContent(
  owner: string,
  repo: string,
  path: string,
  branch: string,
  token?: string
): Promise<string | null> {
  const resp = await fetch(
    `${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`,
    { headers: headers(token) }
  );
  if (!resp.ok) return null;
  const data = await resp.json() as any;
  if (!data.content) return null;
  // GitHub returns base64-encoded content
  return atob(data.content.replace(/\n/g, ""));
}

/** List all repos for a user (public). */
export async function listUserRepos(
  username: string,
  token?: string
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
    for (const r of data) {
      repos.push({ name: r.name, owner: r.owner.login });
    }
    page++;
    if (page > 10) break; // safety limit: 1000 repos max
  }
  return repos;
}

/** Get the diff for a push event (for webhook scanning). */
export async function getPushDiff(
  owner: string,
  repo: string,
  before: string,
  after: string,
  token?: string
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
