import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { PassboxApi } from "@passbox/api-client";
import * as core from "@passbox/core-wasm";
import { setSiteIconSource } from "@passbox/site-icons";
import manifest from "@passbox/site-icons/manifest.json";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PassboxClient } from "./client";
import { memoryStorage } from "./storage";

const require = createRequire(import.meta.url);
const top = (manifest.sites as [string, number, string | null][])[0]?.[0] ?? "";

beforeAll(async () => {
  const wasmPath = require.resolve("@passbox/core-wasm").replace(/\.js$/, "_bg.wasm");
  await core.default({ module_or_path: await readFile(wasmPath) });
});

/** A client whose API records the domains it is asked for. */
function client() {
  const asked: string[] = [];
  const api = new Proxy({} as PassboxApi, {
    get: (_target, name: string) => async (domain: string) => {
      if (name !== "icon") throw new Error(`unexpected call ${name}`);
      asked.push(domain);
      return domain === "server.example" ? { contentType: "image/png", bytes: new Uint8Array([1, 2, 3]) } : null;
    },
  });
  return { client: new PassboxClient({ core, api, storage: memoryStorage() }), asked };
}

function bundled(fail = false) {
  setSiteIconSource({
    async load(size) {
      if (fail) throw new Error("offline");
      const file = require.resolve("@passbox/site-icons/manifest.json").replace(/manifest\.json$/, "");
      const bytes = readFileSync(`${file}packs/web-${size}.pbia`);
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
    async crop(pack, tile) {
      return `data:image/png;base64,${pack.size}x${tile}`;
    },
  });
}

describe("iconUrl", () => {
  beforeEach(() => bundled());

  it("shows bundled sites without asking the server", async () => {
    const { client: c, asked } = client();
    expect(await c.iconUrl(`www.${top}`)).toMatch(/^data:image\/png;base64,\d+x\d+$/);
    expect(await c.iconUrl(top)).toMatch(/^data:image\/png;base64,/);
    expect(asked).toEqual([]);
  });

  it("asks the server for other sites", async () => {
    const { client: c, asked } = client();
    expect(await c.iconUrl("server.example")).toBe("data:image/png;base64,AQID");
    expect(await c.iconUrl("none.example")).toBeNull();
    // Cached in memory.
    expect(await c.iconUrl("server.example")).toBe("data:image/png;base64,AQID");
    expect(asked).toEqual(["server.example", "none.example"]);
  });

  it("falls back to the server when the bundled pack cannot be loaded", async () => {
    bundled(true);
    const { client: c, asked } = client();
    expect(await c.iconUrl("server.example")).toBe("data:image/png;base64,AQID");
    expect(asked).toEqual(["server.example"]);
  });
});
