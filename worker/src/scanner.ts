/**
 * safepush cloud scanner — secret detection engine.
 * Patterns ported from hooks/pre-commit.
 */

export interface ScanMatch {
  pattern: string;
  line: string;
  lineNumber?: number;
  path: string;
  check: string;
  severity: "BLOCK" | "WARN" | "INFO";
}

export interface ScanOptions {
  // Path-level ignore patterns (glob-style: "*.json", "dist/", "src/vendor/*")
  ignorePaths?: string[];
  // File-level ignore patterns for this specific file (from inline comments)
  fileIgnores?: Map<string, Set<string>>; // line number -> set of checks to ignore
}

export interface ScanResult {
  repo: string;
  scannedAt: string;
  totalFiles: number;
  matches: ScanMatch[];
  summary: Record<string, number>;
}

// ── Secret patterns — extended for unquoted values, exports, more token formats ──

// Generic assignment: VAR_NAME=value or export VAR_NAME=value (with or without quotes)
// Catches patterns like: API_KEY=abc123, export TOKEN=ghp_xxx, secret: "value"
function buildAssignedSecret(namePattern: string, minValueLen: number): RegExp {
  return new RegExp(
    `(?:^|\\s|;)(?:export\\s+)?[a-zA-Z0-9_.]*${namePattern}[a-zA-Z0-9_.]*\\s*[=:]\\s*(?:['"\`])?([^\\s'"\`\\n\\r$]{${minValueLen},})(?:['"\`])?`,
    "im"
  );
}

const SECRET_PATTERNS: { regex: RegExp; label: string }[] = [
  // ── Named assignments (unquoted values supported) ──
  { regex: buildAssignedSecret("api[_-]?key", 12), label: "API key in source" },
  { regex: buildAssignedSecret("apikey", 12), label: "API key in source" },
  { regex: buildAssignedSecret("secret", 8), label: "Hardcoded secret" },
  { regex: buildAssignedSecret("token", 12), label: "Hardcoded token" },
  { regex: buildAssignedSecret("access[_-]?token", 12), label: "Hardcoded token" },
  { regex: buildAssignedSecret("password", 4), label: "Hardcoded password" },
  { regex: buildAssignedSecret("passwd", 4), label: "Hardcoded password" },
  { regex: buildAssignedSecret("auth[_-]?token", 12), label: "Hardcoded auth token" },
  { regex: buildAssignedSecret("client[_-]?secret", 8), label: "OAuth client secret" },
  { regex: buildAssignedSecret("client[_-]?id", 12), label: "OAuth client ID" },
  { regex: buildAssignedSecret("webhook[_-]?secret", 8), label: "Webhook secret" },
  { regex: buildAssignedSecret("signing[_-]?key", 8), label: "Signing key" },
  { regex: buildAssignedSecret("encryption[_-]?key", 8), label: "Encryption key" },
  { regex: buildAssignedSecret("jwt[_-]?secret", 8), label: "JWT secret" },
  { regex: buildAssignedSecret("session[_-]?secret", 8), label: "Session secret" },
  { regex: buildAssignedSecret("db[_-]?(url|uri|connection)", 10), label: "Database connection string" },
  { regex: buildAssignedSecret("database[_-]?url", 10), label: "Database URL" },
  { regex: buildAssignedSecret("cf[_-]?api[_-]?token", 10), label: "Cloudflare API token" },

  // ── Well-known token formats (unquoted, anywhere on line) ──
  { regex: /\bghp_[a-zA-Z0-9]{36}\b/, label: "GitHub classic PAT" },
  { regex: /\bgithub_pat_[a-zA-Z0-9_]{22,}\b/, label: "GitHub fine-grained PAT" },
  { regex: /\bgho_[a-zA-Z0-9]{36,}\b/, label: "GitHub OAuth token" },
  { regex: /\bghu_[a-zA-Z0-9]{36,}\b/, label: "GitHub user token" },
  { regex: /\bghs_[a-zA-Z0-9]{36,}\b/, label: "GitHub server token" },
  { regex: /\bghr_[a-zA-Z0-9]{36,}\b/, label: "GitHub refresh token" },
  { regex: /\bsk-[a-zA-Z0-9]{20,}\b/, label: "OpenAI API key" },
  { regex: /\b(?:sk|pk)-(?:ant|proj|org)-[a-zA-Z0-9]{20,}\b/, label: "Anthropic API key" },
  { regex: /\bAKIA[0-9A-Z]{16}\b/, label: "AWS access key ID" },
  { regex: /\b(?:ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b/, label: "AWS STS/temporary key" },
  { regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/, label: "Slack token" },
  { regex: /\b(?:AIza[0-9A-Za-z\-_]{35}|ya29\.[0-9A-Za-z\-_]+)\b/, label: "Google API key / OAuth" },
  { regex: /\bSG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}\b/, label: "SendGrid API key" },
  { regex: /\bacct_[a-zA-Z0-9]{16,}\b/, label: "Twilio account SID" },
  { regex: /\bsk_test_[a-zA-Z0-9]{24,}\b/, label: "Stripe test secret key" },
  { regex: /\bsk_live_[a-zA-Z0-9]{24,}\b/, label: "Stripe live secret key" },
  { regex: /\bpk_live_[a-zA-Z0-9]{24,}\b/, label: "Stripe live publishable key" },
  { regex: /\brk_live_[a-zA-Z0-9]{24,}\b/, label: "Stripe live restricted key" },
  { regex: /\bwhsec_[a-zA-Z0-9]{24,}\b/, label: "Stripe webhook secret" },
  { regex: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/, label: "JWT token" },
  { regex: /\bkey-[a-zA-Z0-9]{20,}\b/, label: "Generic API key (key-xxx format)" },
  { regex: /\btkn-[a-zA-Z0-9]{20,}\b/, label: "Generic token (tkn-xxx format)" },
  { regex: /\bpat-[a-zA-Z0-9]{20,}\b/, label: "Generic PAT (pat-xxx format)" },

  // ── Private key blocks ──
  { regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, label: "Private key block" },
  { regex: /-----BEGIN CERTIFICATE-----/, label: "Certificate block" },

  // ── Credentials in URLs (with auth) — must be in authority section, not query params ──
  { regex: /[a-z]+:\/\/[^:\/\s@]+:[^\/\s@]+@[^\s]+/i, label: "URL with embedded credentials" },

  // ── npm / pip / gem tokens ──
  { regex: /\/\/registry\.npmjs\.org\/:[_\-]?authToken=/i, label: ".npmrc auth token" },
  { regex: /npm_[a-zA-Z0-9]{36}/, label: "npm access token" },

  // ── Git credentials ──
  { regex: /https?:\/\/[^:@\s]+:[^@\s]+@(?:github|gitlab|bitbucket)\./i, label: "Git credentials in URL" },

  // ── Docker / container registry ──
  { regex: /docker login\s+-u\s+\S+\s+-p\s+\S+/i, label: "Docker login with password" },
  { regex: /DOCKER_(?:HUB_)?(?:PASSWORD|TOKEN|AUTH)\s*[=:]\s*\S+/i, label: "Docker auth token" },
];

// ── Sensitive file patterns ──
const SENSITIVE_FILE_PATTERNS = [
  /\.env$/, /\.env\./, /credentials\.json$/, /\.pem$/, /\.key$/,
  /\.pfx$/, /\.p12$/, /id_rsa/, /id_ed25519/, /id_ecdsa/,
  /privatekey/, /\.htpasswd$/, /secrets\.ya?ml$/, /secrets\.json$/,
  /\.npmrc$/, /\.pypirc$/, /\.netrc$/, /\.dockercfg$/,
];

// ── Debug print patterns — per-language rules ──
// console.error/warn/info are often intentional in production — flag at INFO, not WARN.

interface DebugPattern {
  regex: RegExp;
  label: string;
  severity?: "WARN" | "INFO";
  // Per-language restriction: only apply to files with these extensions
  extensions?: string[];
}

const DEBUG_PRINT_PATTERNS: DebugPattern[] = [
  // Real debug (WARN — likely unintentional)
  { regex: /^\s*console\.(log|debug|trace|dir)\(/, label: "Debug print (console)", severity: "WARN", extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"] },
  { regex: /^\s*console\.(warn|error|info)\(/, label: "Console output (likely intentional)", severity: "INFO", extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"] },
  { regex: /^\s*fmt\.(Print|Println|Printf|Sprintf)\(/, label: "Debug print (Go)", extensions: ["go"] },
  { regex: /^\s*(System\.(out|err)\.print(ln)?|System\.err\.println)\(/, label: "Debug print (Java)", extensions: ["java", "kt", "scala"] },
  { regex: /^\s*(Console|Debug)\.Write(Line)?\(/, label: "Debug print (C#)", extensions: ["cs"] },
  { regex: /^\s*println!\s*\(/, label: "Debug print (Rust)", extensions: ["rs"] },
  { regex: /^\s*dbg!\s*\(/, label: "Debug print (Rust)", extensions: ["rs"] },
  { regex: /^\s*\bvar_dump\s*\(/, label: "Debug print (PHP)", extensions: ["php"] },
  { regex: /^\s*\bdump\s*\(/, label: "Debug print (PHP/Symfony)", extensions: ["php"] },
  { regex: /^\s*\bpp\s/, label: "Debug print (Python pp)", extensions: ["py"] },
  { regex: /^\s*print\s*\(/, label: "Debug print (Python)", extensions: ["py"] },
  { regex: /^\s*\bputs\b/, label: "Debug print (Ruby)", extensions: ["rb"] },
  { regex: /^\s*\bprint\s/, label: "Debug print (Ruby)", extensions: ["rb"] },

  // ── Shell (.sh, .bash, .zsh) — echo is standard UI, only flag genuine debug leftovers ──
  // Explicit debug markers in echo or comments
  { regex: /^\s*echo\s+.*(?:DEBUG[:\]]|\[DEBUG\]|#\s*debug)/i, label: "Debug echo (explicit marker)", severity: "INFO", extensions: ["sh", "bash", "zsh"] },
  // set -x / set -o xtrace left active (not inside a guarded block)
  { regex: /^\s*set\s+[-+]\s*x\b|^\s*set\s+-o\s+xtrace\b/, label: "Shell xtrace left active", severity: "INFO", extensions: ["sh", "bash", "zsh"] },
];

// ── Merge conflict markers ──
const MERGE_CONFLICT_PATTERN = /^(<<<<<<<|=======|>>>>>>>)/;

// ── Hardcoded connection patterns ──
const CONNECTION_PATTERNS = [
  { regex: /\b(postgres|postgresql|mysql|mariadb|mongodb(\+srv)?|redis|sqlite|cockroachdb|mssql):\/\/[^\s]+/i, label: "Database URL" },
  { regex: /\bjdbc:[^\s]+/i, label: "JDBC connection string" },
  { regex: /(?:https?|ftp|tcp|udp|ws|wss):\/\/([0-9]{1,3}\.){3}[0-9]{1,3}\b/, label: "Hardcoded IP in URL" },
  { regex: /\b(?:host|server|bind|listen|address|endpoint|proxy|connect)\s*[=:]\s*['"]?([0-9]{1,3}\.){3}[0-9]{1,3}/i, label: "Hardcoded IP in connection config" },
  { regex: /\b(amqp|mqtt|kafka):\/\/[^\s]+/i, label: "Message queue URL" },
];

// ── Absolute path pattern ──
const ABSOLUTE_PATH_PATTERN = /^["']?\/home\/[^\s"']+/;

// ── TODO / FIXME pattern ──
const TODO_PATTERN = /\b(TODO|FIXME|HACK|XXX)\b/;

// ── Helper: does the value look like a variable reference, not a literal? ──
function isVariableReference(assignedValue: string): boolean {
  if (!assignedValue) return true;
  // Env var references: env.X, process.env.X, import.meta.env.X, $VAR, ${VAR}, %VAR%
  if (/^(?:process\.)?env\.\w|[A-Z_]{3,}$|^\$[A-Z_{]|^%[A-Z_]+%$/.test(assignedValue)) return true;
  // Variable references that look like property chains
  if (/^\w+\.\w+/.test(assignedValue)) return true;
  // Pure variable names (like `const password = myVar`)
  if (/^[a-z]\w*$/i.test(assignedValue) && assignedValue.length < 30) return true;
  return false;
}

// ── Helper: does the match look like a function/var declaration, not a secret assignment? ──
function isDeclaration(line: string): boolean {
  // const/let/var/function/async declarations
  if (/^\s*(?:export\s+)?(?:const|let|var|function|async\s+function|class)\s+\w*\s*(?:[=:(]|$)/.test(line)) return true;
  // TypeScript type/property annotations: "password: string;", "token: Token;", "tokens: ArtifactsTokenInfo[];"
  if (/:\s*(?:string|number|boolean|any|void|null|undefined|never|unknown)\b/.test(line)) return true;
  if (/:\s*[A-Z]\w*(?:\[\])?(?:\s*[|&]\s*[A-Z]\w*(?:\[\])?)*\s*[;,)]?\s*$/.test(line.trim())) return true;
  // Method signatures in TS: "dump(): Promise;", "getToken(): string"
  if (/\w+\(\s*[^)]*\)\s*:\s*\w/.test(line.trim())) return true;
  return false;
}

// ── Helper: is the line likely a comment? ──
function isComment(line: string, path: string): boolean {
  const trimmed = line.trim();
  if (!trimmed) return true;

  const ext = path.split(".").pop()?.toLowerCase() || "";

  // Single-line comments by language
  if (["js", "ts", "jsx", "tsx", "go", "rs", "java", "c", "cpp", "h", "cs", "swift", "kt", "scala", "dart"].includes(ext)) {
    if (/^\s*\/\//.test(trimmed)) return true;
  }
  if (["sh", "bash", "zsh", "py", "rb", "pl", "pm", "yaml", "yml", "toml", "cfg", "conf", "tf"].includes(ext)) {
    if (/^\s*#/.test(trimmed)) return true;
  }
  if (["sql"].includes(ext)) {
    if (/^\s*--/.test(trimmed)) return true;
  }
  if (["html", "xml", "md", "mdx"].includes(ext)) {
    if (/^\s*<!--/.test(trimmed)) return true;
  }
  // All languages
  if (/^\s*(\/\/|#|--|;|%|\*)/.test(trimmed) && !/^\s*#!/.test(trimmed)) return true;

  return false;
}

export function scanFile(path: string, content: string, options?: ScanOptions): ScanMatch[] {
  const matches: ScanMatch[] = [];
  const lines = content.split("\n");
  const ext = path.split(".").pop()?.toLowerCase() || "";

  // ── Skip binary / vendor / lock files ──
  const skipPaths = ["node_modules/", "dist/", "build/", ".git/", "target/",
                     "__pycache__/", ".next/", "vendor/", "bower_components/",
                     ".wrangler/", ".turbo/", "coverage/", ".nyc_output/"];
  if (skipPaths.some((d) => path.startsWith(d))) return matches;

  const skipExts = ["png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2", "ttf", "eot",
                    "mp3", "mp4", "webm", "ogg", "pdf", "zip", "gz", "tar", "bz2", "7z",
                    "exe", "dll", "so", "dylib", "bin", "dat", "db", "sqlite"];
  if (skipExts.includes(ext)) return matches;

  // ── Path-level ignore patterns (.safepushignore) ──
  if (options?.ignorePaths) {
    for (const pattern of options.ignorePaths) {
      if (pattern.endsWith("/")) {
        // Directory pattern: "dist/" matches any file under dist/
        if (path.startsWith(pattern)) return matches;
      } else if (pattern.startsWith("*/")) {
        // Wildcard prefix: "*/vendor/*" matches any file with vendor/ in path
        if (path.includes(pattern.slice(2))) return matches;
      } else if (pattern.includes("*")) {
        // Glob-like: convert to regex
        const regex = new RegExp("^" + pattern.replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
        if (regex.test(path)) return matches;
      } else {
        // Exact match or prefix match
        if (path === pattern || path.startsWith(pattern + "/") || (path.split("/").pop() || "") === pattern) return matches;
      }
    }
  }

  const skipFilenames = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                         "Gemfile.lock", "Cargo.lock", "composer.lock",
                         "poetry.lock", "Pipfile.lock", "deno.lock",
                         "bun.lockb", "mix.lock", "go.sum"];

  // Skip generated type declaration files (only types, never secrets)
  if (path.endsWith(".d.ts") || path.endsWith(".d.mts") || path.endsWith(".d.cts")) return matches;
  const fname = path.split("/").pop() || path;
  if (skipFilenames.includes(fname)) return matches;

  // ── Secrets (skip comments) ──
  for (const { regex, label } of SECRET_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isComment(line, path)) continue;
      if (regex.test(line)) {
        // Skip declarations: const/let/var/function names
        if (isDeclaration(line)) continue;
        // Skip false positives: placeholder/default values
        const val = line.toLowerCase();
        if (/\b(your_?|example_?|test_?|sample_?|dummy_?|changeme|replaceme|xxxx+|abcde+|12345+|password[_-]?here)/i.test(val)) continue;
        // Skip compound camelCase identifiers: formFieldInputShowPasswordButton, setApiKey, etc.
        if (/[a-z][A-Z](?:.*(?:password|secret|token|api[_-]?key))|(?:password|secret|token|api[_-]?key).*[A-Z][a-z]/i.test(line)) continue;
        // Skip if the assigned value is an env var or variable reference
        const match = line.match(regex);
        if (match && match[1] && isVariableReference(match[1])) continue;
        matches.push({
          pattern: label,
          line: line.trim().slice(0, 200),
          lineNumber: i + 1,
          path,
          check: "secrets",
          severity: "BLOCK",
        });
      }
    }
  }

  // ── Sensitive files ──
  const filename = path.split("/").pop() || path;
  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    if (pattern.test(filename)) {
      matches.push({
        pattern: "Sensitive file",
        line: filename,
        path,
        check: "sensitive_files",
        severity: "BLOCK",
      });
      break;
    }
  }

  // ── Merge conflicts ──
  for (let i = 0; i < lines.length; i++) {
    if (MERGE_CONFLICT_PATTERN.test(lines[i])) {
      matches.push({
        pattern: "Merge conflict marker",
        line: lines[i].trim(),
        lineNumber: i + 1,
        path,
        check: "merge_conflicts",
        severity: "BLOCK",
      });
    }
  }

  // ── Debug prints ──
  for (const { regex, label, severity: sev, extensions: exts } of DEBUG_PRINT_PATTERNS) {
    if (exts && !exts.includes(ext)) continue; // per-language rule — skip if extension doesn't match
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isComment(line, path)) continue;
      if (regex.test(line)) {
        matches.push({
          pattern: label,
          line: line.trim().slice(0, 150),
          lineNumber: i + 1,
          path,
          check: "debug_prints",
          severity: sev || "WARN",
        });
      }
    }
  }

  // ── Parse per-check inline suppressions ──
  // "// safepush:ignore:secrets" suppresses only secrets on the next line
  // "// safepush:ignore" suppresses all checks on the next line
  // "# safepush:ignore:hardcoded_connections" suppresses only that check
  const suppressedChecks: Map<number, Set<string>> = new Map();
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/safepush:\s*ignore(?::(\w+))?/i);
    if (m) {
      const targetLine = i; // suppress THIS line
      const check = m[1]?.toLowerCase(); // specific check, or undefined = all
      if (!suppressedChecks.has(targetLine)) suppressedChecks.set(targetLine, new Set());
      if (check) suppressedChecks.get(targetLine)!.add(check);
      else suppressedChecks.get(targetLine)!.add("*"); // "*" means all checks
    }
  }

  // ── Single-pass: connections, absolute paths, TODO/FIXME ──
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ignores = suppressedChecks.get(i);

    // Helper: should this check be suppressed on this line?
    function isSuppressed(check: string): boolean {
      if (!ignores) return false;
      return ignores.has("*") || ignores.has(check.toLowerCase());
    }

    const isCommentLine = isComment(line, path);

    // Hardcoded connections (non-comment lines only)
    if (!isCommentLine && !isSuppressed("hardcoded_connections")) {
      for (const { regex, label } of CONNECTION_PATTERNS) {
        const m = line.match(regex);
        if (m) {
          const matched = m[0];
          if (!/^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)$/.test(matched)) {
            matches.push({
              pattern: label,
              line: line.trim().slice(0, 150),
              lineNumber: i + 1,
              path,
              check: "hardcoded_connections",
              severity: "WARN",
            });
          }
        }
      }
    }

    // Absolute paths
    if (!isSuppressed("absolute_paths") && ABSOLUTE_PATH_PATTERN.test(line)) {
      matches.push({
        pattern: "Absolute path",
        line: line.trim().slice(0, 150),
        lineNumber: i + 1,
        path,
        check: "absolute_paths",
        severity: "INFO",
      });
    }

    // TODO / FIXME (comments only)
    if (!isSuppressed("todo_fixme") && isCommentLine && TODO_PATTERN.test(line)) {
      matches.push({
        pattern: "TODO / FIXME",
        line: line.trim().slice(0, 120),
        lineNumber: i + 1,
        path,
        check: "todo_fixme",
        severity: "INFO",
      });
    }
  }

  return matches;
}

export function summarize(matches: ScanMatch[]): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const m of matches) {
    summary[m.check] = (summary[m.check] || 0) + 1;
  }
  return summary;
}
