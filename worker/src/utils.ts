/** Shared helpers for the safepush Worker. */

const REPO_SLUG = /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,99})$/;

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function escapeJs(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/</g, "\\x3c");
}

export function validateRepoSlug(value: string, field: string): string | null {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 100) return `${field} is required (max 100 chars)`;
  if (!REPO_SLUG.test(trimmed)) {
    return `${field} must start with alphanumeric and contain only letters, numbers, ., _, -`;
  }
  return null;
}

export function parseJsonSafe<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function checkRateLimit(
  kv: KVNamespace,
  key: string,
  limit = 30,
  windowSec = 60,
): Promise<boolean> {
  const storageKey = `ratelimit:${key}`;
  const current = Number.parseInt((await kv.get(storageKey)) || "0", 10);
  if (current >= limit) return false;
  await kv.put(storageKey, String(current + 1), { expirationTtl: windowSec });
  return true;
}

export function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip")
    || request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || "unknown";
}

export async function mapConcurrent<T, R>(
  items: T[],
  fn: (item: T) => Promise<R>,
  concurrency = 5,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let index = 0;

  async function worker(): Promise<void> {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i]);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, () => worker()),
  );
  return results;
}