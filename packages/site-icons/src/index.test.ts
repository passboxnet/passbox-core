import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import manifest from "../manifest.json";
import {
  bundledSiteIcon,
  isBundledSite,
  type PackSize,
  parseAtlas,
  setSiteIconSource,
  siteIconKeys,
  tilePosition,
} from "./index";

const packPath = (name: string) => fileURLToPath(new URL(`../packs/${name}`, import.meta.url));
const packFile = (size: PackSize) => packPath(`web-${size}.pbia`);
const sites = manifest.sites as [string, number, string | null][];
/** The most popular bundled site (in both packs). */
const top = sites[0]?.[0] ?? "";

let loads: PackSize[] = [];

beforeEach(() => {
  loads = [];
  setSiteIconSource({
    async load(size) {
      loads.push(size);
      const bytes = readFileSync(packFile(size));
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
    async crop(pack, tile) {
      return `data:test,${pack.size}:${tile}`;
    },
  });
});

describe("packs", () => {
  it("hold the sites of the manifest, each on its own tile", () => {
    for (const size of [32, 64] as const) {
      const pack = parseAtlas(readFileSync(packFile(size)));
      const info = manifest.files[`web-${size}.pbia` as keyof typeof manifest.files];
      expect(pack.size).toBe(size);
      expect(pack.tiles.size).toBe(info.icons);
      expect(new Set(pack.tiles.values()).size).toBe(pack.tiles.size);
      expect(String.fromCharCode(...pack.image.subarray(8, 12))).toBe("WEBP");
      const last = tilePosition(pack, pack.tiles.size - 1);
      expect(last.x).toBeLessThan(pack.columns * size);
    }
    const all = parseAtlas(readFileSync(packFile(32)));
    for (const [domain] of sites) expect(all.tiles.has(domain)).toBe(true);
  });

  it("stay within the size budget of the web app and the extension (3 MB)", () => {
    const total = statSync(packFile(32)).size + statSync(packFile(64)).size;
    expect(total).toBeLessThanOrEqual(3 * 1024 * 1024);
  });

  it("refuse other files", () => {
    expect(() => parseAtlas(new TextEncoder().encode("not a pack at all"))).toThrow();
    expect(() =>
      parseAtlas(readFileSync(fileURLToPath(new URL("../mobile/site-icons-64.pbic", import.meta.url)))),
    ).toThrow();
  });
});

describe("bundledSiteIcon", () => {
  it("finds popular sites by host, also with www.", async () => {
    expect(await bundledSiteIcon(top, 1)).toMatch(/^data:test,32:\d+$/);
    expect(await bundledSiteIcon(`www.${top}`, 1)).toMatch(/^data:test,32:\d+$/);
    expect(await bundledSiteIcon(`${top.toUpperCase()}.`, 1)).toMatch(/^data:test,32:/);
    expect(await isBundledSite(`www.${top}`)).toBe(true);
  });

  it("uses the 64 px pack on high-density screens", async () => {
    expect(await bundledSiteIcon(top, 2)).toMatch(/^data:test,64:\d+$/);
    expect(loads).toEqual([64]);
  });

  it("answers null for other sites, and nothing for invalid hosts", async () => {
    expect(await bundledSiteIcon("not-bundled.example", 2)).toBeNull();
    expect(await isBundledSite("not-bundled.example")).toBe(false);
    loads = [];
    for (const host of ["", "localhost", "192.168.1.1", "exa mple.com", `sub.${top}x`]) {
      expect(await bundledSiteIcon(host, 1)).toBeNull();
    }
    // A subdomain is a different site: only www. maps to the bare name.
    expect(await isBundledSite(`login.not-${top}`)).toBe(false);
  });

  it("loads each pack once and retries after a failure", async () => {
    let fail = true;
    setSiteIconSource({
      async load(size) {
        loads.push(size);
        if (fail) throw new Error("offline");
        const bytes = readFileSync(packFile(size));
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
      },
      async crop(pack, tile) {
        return `data:test,${pack.size}:${tile}`;
      },
    });
    await expect(bundledSiteIcon(top, 1)).rejects.toThrow("offline");
    fail = false;
    expect(await bundledSiteIcon(top, 1)).toMatch(/^data:test,32:/);
    expect(await bundledSiteIcon(`www.${top}`, 1)).toMatch(/^data:test,32:/);
    expect(loads).toEqual([32, 32]);
  });
});

describe("siteIconKeys", () => {
  it("normalizes host names", () => {
    expect(siteIconKeys("WWW.Example.COM.")).toEqual(["www.example.com", "example.com"]);
    expect(siteIconKeys("accounts.example.com")).toEqual(["accounts.example.com"]);
    expect(siteIconKeys("10.0.0.1")).toEqual([]);
    expect(siteIconKeys("intranet")).toEqual([]);
  });
});
