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

export interface ScanResult {
  repo: string;
  scannedAt: string;
  totalFiles: number;
  matches: ScanMatch[];
  summary: Record<string, number>;
}

// ── Secret patterns (same as hooks/pre-commit line 138-150) ──
const SECRET_PATTERNS: { regex: RegExp; label: string }[] = [
  { regex: /[a-zA-Z0-9_]*[_-]?(api[_-]?key|apikey|API_KEY)\s*[=:]\s*['"][a-zA-Z0-9_-]{12,}['"]/i, label: "API key in source" },
  { regex: /[a-zA-Z0-9_]*[_-]?(secret|SECRET)\s*[=:]\s*['"][a-zA-Z0-9_-]{8,}['"]/i, label: "Hardcoded secret" },
  { regex: /[a-zA-Z0-9_]*[_-]?(token|TOKEN|access_token)\s*[=:]\s*['"][a-zA-Z0-9_.-]{12,}['"]/i, label: "Hardcoded token" },
  { regex: /[a-zA-Z0-9_]*[_-]?(password|PASSWORD|passwd)\s*[=:]\s*['"][^'"]{4,}['"]/i, label: "Hardcoded password" },
  { regex: /sk-[a-zA-Z0-9]{20,}/, label: "OpenAI API key" },
  { regex: /ghp_[a-zA-Z0-9]{36}/, label: "GitHub classic PAT" },
  { regex: /github_pat_[a-zA-Z0-9_]{22,}/, label: "GitHub fine-grained PAT" },
  { regex: /AKIA[0-9A-Z]{16}/, label: "AWS access key" },
  { regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/, label: "Slack token" },
];

// ── Sensitive file patterns ──
const SENSITIVE_FILE_PATTERNS = [
  /\.env$/, /\.env\./, /credentials\.json$/, /\.pem$/, /\.key$/,
  /\.pfx$/, /\.p12$/, /id_rsa/, /id_ed25519/, /id_ecdsa/,
  /privatekey/, /\.htpasswd$/, /secrets\.ya?ml$/, /secrets\.json$/,
];

// ── Debug print patterns (11 languages) ──
const DEBUG_PRINT_PATTERN =
  /^\s*(console\.(log|debug|warn|error|info|trace)\(|fmt\.(Print|Println|Printf|Sprintf)\(|System\.(out|err)\.print(ln)?\(|(Console|Debug)\.Write(Line)?\(|println!|dbg!|\bprintln\b|print\(|printf\(|echo\s|var_dump\(|dump\(|puts\b|\bpp\b)/;

// ── Merge conflict markers ──
const MERGE_CONFLICT_PATTERN = /^(<<<<<<<|=======|>>>>>>>)/;

// ── Hardcoded connection patterns ──
const CONNECTION_PATTERNS = [
  { regex: /(postgres|mysql|mongodb|redis|sqlite):\/\/[^\s]+/i, label: "Database URL" },
  { regex: /[a-z]+:\/\/[^@]+@[^\s]+/i, label: "URL with credentials" },
  { regex: /jdbc:[^\s]+/i, label: "JDBC connection string" },
  { regex: /\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/, label: "Hardcoded IP address" },
];

// ── Absolute path pattern ──
const ABSOLUTE_PATH_PATTERN = /^["']?\/home\/[^\s"']+/;

// ── TODO / FIXME pattern ──
const TODO_PATTERN = /\b(TODO|FIXME|HACK|XXX)\b/;

export function scanFile(path: string, content: string): ScanMatch[] {
  const matches: ScanMatch[] = [];
  const lines = content.split("\n");

  // ---- Secrets ----
  for (const { regex, label } of SECRET_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip comment lines
      if (/^\s*(\/\/|#|--|;|\*)/.test(line.trim())) continue;
      if (regex.test(line)) {
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

  // ---- Sensitive files ----
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

  // ---- Merge conflicts ----
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

  // ---- Debug prints ----
  for (let i = 0; i < lines.length; i++) {
    if (DEBUG_PRINT_PATTERN.test(lines[i])) {
      matches.push({
        pattern: "Debug print",
        line: lines[i].trim().slice(0, 150),
        lineNumber: i + 1,
        path,
        check: "debug_prints",
        severity: "WARN",
      });
    }
  }

  // ---- Hardcoded connections ----
  for (const { regex, label } of CONNECTION_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*(\/\/|#|--|;)/.test(line.trim())) continue;
      if (regex.test(line) && !/localhost|127\.0\.0\.1|0\.0\.0\.0|::1/.test(line)) {
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

  // ---- Absolute paths ----
  for (let i = 0; i < lines.length; i++) {
    if (ABSOLUTE_PATH_PATTERN.test(lines[i])) {
      matches.push({
        pattern: "Absolute path",
        line: lines[i].trim().slice(0, 150),
        lineNumber: i + 1,
        path,
        check: "absolute_paths",
        severity: "INFO",
      });
    }
  }

  // ---- TODO / FIXME ----
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*(\/\/|#|--)/.test(lines[i].trim()) && TODO_PATTERN.test(lines[i])) {
      matches.push({
        pattern: "TODO / FIXME",
        line: lines[i].trim().slice(0, 120),
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
