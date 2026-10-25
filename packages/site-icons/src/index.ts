/**
 * Website icons of the most popular sites, bundled with the web app, the
 * desktop app and the extension (iOS and Android bundle their own pack, read
 * by the Rust client). Clients look here first and never ask the Passbox
 * server for a bundled site, so the server learns only the less popular
 * domains in a vault. See docs/architecture/item-extras.md#website-icons.
 *
 * Two atlas packs (src/pack.ts): 32 px for every bundled site and 64 px for
 * the most popular ones, used on screens with more than one pixel per
 * point. A pack is downloaded (it is an asset of the app, not a request to
 * anyone else) when the first icon is needed, and decoded once.
 *
 * The icons belong to the websites' owners and only identify the sites;
 * source and ranking: manifest.json and THIRD_PARTY_NOTICES.md. Regenerate
 * with `node scripts/update-site-icons.mjs`.
 */
import { type AtlasPack, parseAtlas, tilePosition } from "./pack";

export type { AtlasPack } from "./pack";
export { parseAtlas, tilePosition } from "./pack";

export type PackSize = 32 | 64;

/** Literal URLs, so bundlers (Vite) copy the packs as assets. */
const PACK_URLS: Record<PackSize, string> = {
  32: new URL("../packs/web-32.pbia", import.meta.url).href,
  64: new URL("../packs/web-64.pbia", import.meta.url).href,
};

/** How packs are loaded and tiles cut out (replaceable for tests). */
export interface SiteIconSource {
  /** The bytes of a pack. */
  load(size: PackSize): Promise<ArrayBuffer>;
  /** One tile of a pack's atlas as a `data:` URL. */
  crop(pack: AtlasPack, tile: number): Promise<string>;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/**
 * Browsers, the desktop app's web view and extension service workers:
 * `fetch` for the pack, `createImageBitmap` to decode the atlas once, and
 * a canvas (an `OffscreenCanvas` where there is no document) per tile.
 */
export function browserSiteIconSource(): SiteIconSource {
  const atlases = new WeakMap<AtlasPack, Promise<ImageBitmap>>();
  return {
    async load(size) {
      const response = await fetch(PACK_URLS[size]);
      if (!response.ok) throw new Error(`website icon pack: HTTP ${response.status}`);
      return response.arrayBuffer();
    },
    async crop(pack, tile) {
      let atlas = atlases.get(pack);
      if (!atlas) {
        atlas = createImageBitmap(new Blob([pack.image], { type: "image/webp" }));
        atlases.set(pack, atlas);
      }
      const bitmap = await atlas;
      const { x, y } = tilePosition(pack, tile);
      if (typeof OffscreenCanvas !== "undefined") {
        const canvas = new OffscreenCanvas(pack.size, pack.size);
        canvas.getContext("2d")?.drawImage(bitmap, x, y, pack.size, pack.size, 0, 0, pack.size, pack.size);
        const png = await canvas.convertToBlob({ type: "image/png" });
        return `data:image/png;base64,${bytesToBase64(new Uint8Array(await png.arrayBuffer()))}`;
      }
      const canvas = document.createElement("canvas");
      canvas.width = pack.size;
      canvas.height = pack.size;
      canvas.getContext("2d")?.drawImage(bitmap, x, y, pack.size, pack.size, 0, 0, pack.size, pack.size);
      return canvas.toDataURL("image/png");
    },
  };
}

let source: SiteIconSource = browserSiteIconSource();
const packs = new Map<PackSize, Promise<AtlasPack>>();
const icons = new Map<string, Promise<string>>();

/** Replaces how packs are loaded (tests) and forgets everything loaded. */
export function setSiteIconSource(next: SiteIconSource): void {
  source = next;
  packs.clear();
  icons.clear();
}

function loadPack(size: PackSize): Promise<AtlasPack> {
  let pack = packs.get(size);
  if (!pack) {
    pack = source.load(size).then(parseAtlas);
    // A failed download is tried again next time.
    pack.catch(() => packs.delete(size));
    packs.set(size, pack);
  }
  return pack;
}

/**
 * The names a host is bundled under: the host itself and, for `www.`
 * hosts, the name without it. Lower case, without a trailing dot; empty
 * for anything that is not a plain host name with a dot.
 */
export function siteIconKeys(host: string): string[] {
  const name = host.trim().toLowerCase().replace(/\.$/, "");
  if (name.length > 253 || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(name) || /^[\d.]+$/.test(name)) return [];
  return name.startsWith("www.") ? [name, name.slice(4)] : [name];
}

/** The tile of `host` in `pack`, if bundled. */
function find(pack: AtlasPack, host: string): number | undefined {
  for (const key of siteIconKeys(host)) {
    const tile = pack.tiles.get(key);
    if (tile !== undefined) return tile;
  }
  return undefined;
}

/**
 * Whether `host` has a bundled icon. Clients then never ask the server for
 * it. Rejects when the pack cannot be loaded.
 */
export async function isBundledSite(host: string): Promise<boolean> {
  if (siteIconKeys(host).length === 0) return false;
  return find(await loadPack(32), host) !== undefined;
}

/**
 * The bundled icon of `host` as a `data:` URL for an `<img>`, or `null`
 * when it has none. `scale` is the device's pixels per point (default
 * `devicePixelRatio`; 2 where there is none, as in the extension's service
 * worker, whose icons show in pages it cannot see): above 1 the 64 px icon
 * is used where there is one. Rejects when the pack cannot be loaded or
 * decoded.
 */
export async function bundledSiteIcon(host: string, scale?: number): Promise<string | null> {
  if (siteIconKeys(host).length === 0) return null;
  const pixels = scale ?? (typeof devicePixelRatio === "number" ? devicePixelRatio : 2);
  const sizes: PackSize[] = pixels > 1 ? [64, 32] : [32];
  for (const size of sizes) {
    const pack = await loadPack(size);
    const tile = find(pack, host);
    if (tile === undefined) continue;
    const key = `${size}:${tile}`;
    let icon = icons.get(key);
    if (!icon) {
      icon = source.crop(pack, tile);
      icon.catch(() => icons.delete(key));
      icons.set(key, icon);
    }
    return icon;
  }
  return null;
}
