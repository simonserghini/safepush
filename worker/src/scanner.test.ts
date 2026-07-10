import { describe, expect, it } from "vitest";
import { scanFile } from "./scanner";

describe("scanFile", () => {
  it("detects hardcoded secrets", () => {
    const matches = scanFile("settings.ts", "token = ghp_1234567890abcdefghijklmnopqrstuvwxyz");
    expect(matches.some(m => m.check === "secrets")).toBe(true);
  });

  it("honors safepush:ignore on the next line for secrets", () => {
    const content = [
      "// safepush:ignore:secrets",
      'const x = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";',
    ].join("\n");
    const matches = scanFile("config.ts", content);
    expect(matches.filter(m => m.check === "secrets")).toHaveLength(0);
  });

  it("honors safepush:ignore on the next line for debug prints", () => {
    const content = [
      "// safepush:ignore:debug_prints",
      "console.log('debug');",
    ].join("\n");
    const matches = scanFile("app.ts", content);
    expect(matches.filter(m => m.check === "debug_prints")).toHaveLength(0);
  });

  it("honors safepush:ignore-file for sensitive files", () => {
    const content = "// safepush:ignore-file:sensitive_files\nSECRET=value\n";
    const matches = scanFile(".env", content);
    expect(matches.filter(m => m.check === "sensitive_files")).toHaveLength(0);
  });

  it("flags sensitive filenames by default", () => {
    const matches = scanFile(".env", "API_KEY=test\n");
    expect(matches.some(m => m.check === "sensitive_files")).toBe(true);
  });

  it("ignores bind-all and private IPs in connection config", () => {
    const content = [
      "app.run(host='0.0.0.0', port=5001)",
      "app.run(host='127.0.0.1', port=5001)",
      "app.run(host='192.168.1.10', port=5001)",
    ].join("\n");
    const matches = scanFile("main.py", content);
    expect(matches.filter(m => m.check === "hardcoded_connections")).toHaveLength(0);
  });

  it("flags public IPs in connection config and URLs", () => {
    const content = [
      "app.run(host='93.184.216.34', port=5001)",
      "fetch('http://8.8.8.8/health')",
    ].join("\n");
    const matches = scanFile("main.py", content);
    expect(matches.filter(m => m.check === "hardcoded_connections")).toHaveLength(2);
  });
});