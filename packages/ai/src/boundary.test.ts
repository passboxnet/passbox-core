/**
 * Build rule: AI code gets no keys and no vault
 * access. This package must not depend on or import the core
 * (`@passbox/core-wasm`) or the client (`@passbox/client`, which contains
 * the core). The lint configuration (biome.json) blocks the imports too.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(import.meta.dirname, "..");
const FORBIDDEN = ["@passbox/core-wasm", "@passbox/client", "@passbox/api-client"];

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : /\.(ts|tsx|js|mjs)$/.test(name) ? [path] : [];
  });
}

describe("package boundary", () => {
  it("declares no dependency on the core or the client", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as Record<string, Record<string, string>>;
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies });
    for (const name of FORBIDDEN) expect(deps, `packages/ai must not depend on ${name}`).not.toContain(name);
  });

  it("imports nothing from the core, the client or other packages' sources", () => {
    const files = sources(join(ROOT, "src"));
    expect(files.length).toBeGreaterThan(3);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      const specifiers = [
        ...text.matchAll(/(?:import|export)[^"'`]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g),
      ].map((m) => m[1] ?? m[2] ?? "");
      for (const spec of specifiers) {
        const bad =
          FORBIDDEN.some((f) => spec === f || spec.startsWith(`${f}/`)) ||
          spec.includes("core-wasm") ||
          /^(\.\.\/){2,}/.test(spec);
        expect(bad, `${file} imports ${spec}: AI code gets no keys (docs/architecture/ai-gateway.md)`).toBe(false);
      }
    }
  });
});
