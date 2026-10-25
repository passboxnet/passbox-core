#!/usr/bin/env node
/**
 * Refreshes the bundled brand icons in packages/brand-icons.
 *
 * For every service in packages/brand-icons/services.json it loads the
 * service's homepage, reads the icons its HTML links (`<link rel="icon">`,
 * `apple-touch-icon`), and downloads the best one: the largest
 * apple-touch-icon first, then an SVG icon, then the largest PNG, then
 * /apple-touch-icon.png and /favicon.ico. A service may name its icon URL
 * directly (`icon`), or the class of an element whose <img> shows the app
 * icon (`imageClass`). The icon is decoded and scaled to a 64 px PNG in a
 * headless Chromium (from the e2e package's Playwright), so no image
 * library is needed. Results go to packages/brand-icons/icons/<id>.png,
 * packages/brand-icons/manifest.json and packages/brand-icons/src/generated.ts.
 *
 * The apps never contact these services for icons at run time: everything is
 * bundled. The marks belong to their owners (see THIRD_PARTY_NOTICES.md).
 *
 *   node scripts/update-brand-icons.mjs            # all services
 *   node scripts/update-brand-icons.mjs okta github # some of them
 *
 * Downloads use curl (it honours HTTPS_PROXY). Icons that cannot be fetched
 * keep their previous file; the script lists them at the end.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE = join(ROOT, "packages/brand-icons");
const SIZE = 64;
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const MAX_BYTES = 2_000_000;

const { services } = JSON.parse(readFileSync(join(PACKAGE, "services.json"), "utf8"));
const manifestPath = join(PACKAGE, "manifest.json");
const previous = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, "utf8")).icons : [];
const only = new Set(process.argv.slice(2));

mkdirSync(join(PACKAGE, "icons"), { recursive: true });
mkdirSync(join(PACKAGE, "src"), { recursive: true });
const work = mkdtempSync(join(tmpdir(), "passbox-brand-icons-"));
let counter = 0;

/** Downloads `url` with curl. Returns the bytes, content type and final URL, or undefined. */
function download(url, accept) {
  const file = join(work, `d${counter++}`);
  try {
    const out = execFileSync(
      "curl",
      [
        "-sSL",
        "--max-time",
        "20",
        "--max-redirs",
        "5",
        "--max-filesize",
        String(MAX_BYTES),
        "--proto",
        "=https",
        "-A",
        UA,
        "-H",
        `Accept: ${accept}`,
        "-H",
        "Accept-Language: en-US,en;q=0.8",
        "-o",
        file,
        "-w",
        "%{http_code}\\n%{content_type}\\n%{url_effective}",
        url,
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    const [status = "", type = "", finalUrl = url] = out.trim().split("\n");
    if (!status.startsWith("2") || !existsSync(file)) return undefined;
    return { bytes: readFileSync(file), type: (type || "").split(";")[0].toLowerCase(), url: finalUrl };
  } catch {
    return undefined;
  } finally {
    rmSync(file, { force: true });
  }
}

function attributes(tag) {
  const result = {};
  for (const match of tag.matchAll(/([a-zA-Z:-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g)) {
    result[match[1].toLowerCase()] = match[3] ?? match[4] ?? match[5] ?? "";
  }
  return result;
}

function decodeEntities(value) {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&#x2F;/gi, "/")
    .replace(/&quot;/g, '"');
}

/** Icon candidates from a page's HTML, best first. */
function candidates(html, pageUrl, imageClass) {
  if (imageClass) {
    const pattern = new RegExp(`class="${imageClass}"[^>]*>\\s*<img\\b[^>]*\\bsrc="([^"]+)"`, "i");
    const src = pattern.exec(html)?.[1];
    if (src) return [new URL(decodeEntities(src), pageUrl).href];
  }
  const base = /<base\b[^>]*href\s*=\s*["']([^"']+)["']/i.exec(html)?.[1];
  const baseUrl = base ? new URL(decodeEntities(base), pageUrl).href : pageUrl;
  const found = [];
  for (const [tag] of html.matchAll(/<link\b[^>]*>/gi)) {
    const attrs = attributes(tag);
    const rel = (attrs.rel ?? "").toLowerCase().split(/\s+/);
    if (!attrs.href || rel.includes("mask-icon")) continue;
    const touch = rel.some((r) => r.startsWith("apple-touch-icon"));
    if (!touch && !rel.includes("icon")) continue;
    // Icons only for dark browser chrome often vanish on a light tile.
    if (/prefers-color-scheme:\s*dark/i.test(attrs.media ?? "")) continue;
    let href;
    try {
      href = new URL(decodeEntities(attrs.href), baseUrl).href;
    } catch {
      continue;
    }
    const svg = (attrs.type ?? "").includes("svg") || /\.svg(\?|$)/i.test(href);
    const sizes = (attrs.sizes ?? "")
      .toLowerCase()
      .split(/\s+/)
      .map((s) => (s === "any" ? 512 : Number.parseInt(s, 10)))
      .filter((n) => Number.isFinite(n));
    const size = sizes.length ? Math.max(...sizes) : touch ? 180 : svg ? 512 : 32;
    // apple-touch-icon first, then SVG, then by size.
    const score = (touch ? 10_000 : 0) + (svg ? 5_000 : 0) + size;
    found.push({ href, score });
  }
  found.sort((a, b) => b.score - a.score);
  const origin = new URL(pageUrl).origin;
  const list = [...new Set(found.map((c) => c.href))];
  for (const fallback of [`${origin}/apple-touch-icon.png`, `${origin}/favicon.ico`]) {
    if (!list.includes(fallback)) list.push(fallback);
  }
  return list;
}

function sniffType(bytes, declared, url) {
  const head = bytes.subarray(0, 16);
  if (head[0] === 0x89 && head[1] === 0x50) return "image/png";
  if (head[0] === 0x00 && head[1] === 0x00 && head[2] === 0x01) return "image/x-icon";
  if (head[0] === 0xff && head[1] === 0xd8) return "image/jpeg";
  if (head.toString("ascii", 0, 3) === "GIF") return "image/gif";
  if (head.toString("ascii", 0, 4) === "RIFF" && head.toString("ascii", 8, 12) === "WEBP") return "image/webp";
  const text = bytes.subarray(0, 512).toString("utf8").trimStart().toLowerCase();
  if (text.startsWith("<svg") || (text.startsWith("<?xml") && text.includes("<svg")) || declared.includes("svg")) {
    return text.includes("<svg") || /\.svg(\?|$)/i.test(url) ? "image/svg+xml" : undefined;
  }
  return undefined;
}

const require = createRequire(join(ROOT, "e2e/package.json"));
const { chromium } = require("@playwright/test");
const browser = await chromium.launch();
const page = await browser.newPage();
await page.setContent("<!doctype html><title>icons</title>");

/** Decodes an image data URL in Chromium and scales it into a SIZE×SIZE PNG. */
async function render(dataUrl) {
  return page.evaluate(
    async ({ dataUrl, size }) => {
      const img = new Image();
      img.src = dataUrl;
      try {
        await img.decode();
      } catch {
        return null;
      }
      const w = img.naturalWidth || size;
      const h = img.naturalHeight || size;
      const canvas = document.createElement("canvas");
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext("2d");
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = "high";
      const scale = Math.min(size / w, size / h);
      const dw = w * scale;
      const dh = h * scale;
      ctx.drawImage(img, (size - dw) / 2, (size - dh) / 2, dw, dh);
      const pixels = ctx.getImageData(0, 0, size, size).data;
      let visible = 0;
      for (let i = 3; i < pixels.length; i += 4) if (pixels[i] > 16) visible++;
      // Opaque corners and edges: a full-bleed app icon that fills its tile.
      const corner = (x, y) => pixels[(y * size + x) * 4 + 3];
      const half = size / 2;
      const bleed = [
        corner(3, 3),
        corner(size - 4, 3),
        corner(3, size - 4),
        corner(size - 4, size - 4),
        corner(half, 3),
        corner(3, half),
        corner(half, size - 4),
        corner(size - 4, half),
      ].every((a) => a > 240);
      return {
        png: canvas.toDataURL("image/png"),
        natural: Math.min(w, h),
        svg: dataUrl.startsWith("data:image/svg"),
        bleed,
        blank: visible < size * size * 0.02,
      };
    },
    { dataUrl, size: SIZE },
  );
}

async function fetchIcon(service) {
  const urls = [];
  if (service.icon) urls.push(service.icon);
  else {
    const pageResponse = download(service.homepage, "text/html,application/xhtml+xml");
    if (pageResponse)
      urls.push(...candidates(pageResponse.bytes.toString("utf8"), pageResponse.url, service.imageClass));
    else {
      const origin = new URL(service.homepage).origin;
      urls.push(`${origin}/apple-touch-icon.png`, `${origin}/favicon.ico`);
    }
  }
  let best;
  for (const url of urls.slice(0, 8)) {
    let response;
    if (url.startsWith("data:")) {
      const match = /^data:([^;,]+)(;base64)?,(.*)$/s.exec(url);
      if (!match) continue;
      const bytes = match[2] ? Buffer.from(match[3], "base64") : Buffer.from(decodeURIComponent(match[3]));
      response = { bytes, type: match[1], url };
    } else {
      response = download(url, "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8");
    }
    if (!response) continue;
    const type = sniffType(response.bytes, response.type, url);
    if (!type) continue;
    const result = await render(`data:${type};base64,${response.bytes.toString("base64")}`);
    if (!result || result.blank) continue;
    const quality = result.svg ? 512 : result.natural;
    if (!best || quality > best.quality)
      best = { ...result, quality, source: url.startsWith("data:") ? service.homepage : url };
    if (quality >= 48) break;
  }
  return best && best.quality >= 16 ? best : undefined;
}

const today = new Date().toISOString().slice(0, 10);
const icons = [];
const failed = [];
for (const service of services) {
  const old = previous.find((entry) => entry.id === service.id);
  const file = join(PACKAGE, "icons", `${service.id}.png`);
  if (only.size && !only.has(service.id)) {
    if (old && existsSync(file))
      icons.push({ ...old, name: service.name, domain: service.domain, aliases: service.aliases });
    continue;
  }
  process.stdout.write(`${service.id.padEnd(26)}`);
  const icon = await fetchIcon(service);
  if (icon) {
    writeFileSync(file, Buffer.from(icon.png.split(",")[1], "base64"));
    icons.push({
      id: service.id,
      name: service.name,
      domain: service.domain,
      aliases: service.aliases,
      source: icon.source,
      fetched: today,
      bleed: icon.bleed,
    });
    console.log(`${icon.svg ? "svg" : `${icon.natural}px`}${icon.bleed ? " full" : ""}  ${icon.source}`);
  } else {
    failed.push(service.id);
    if (old && existsSync(file))
      icons.push({ ...old, name: service.name, domain: service.domain, aliases: service.aliases });
    console.log(old ? "FAILED (kept the previous icon)" : "FAILED (no icon)");
  }
}
await browser.close();
rmSync(work, { recursive: true, force: true });

writeFileSync(
  manifestPath,
  `${JSON.stringify({ $comment: "Generated by scripts/update-brand-icons.mjs. Do not edit.", icons }, null, 2)}\n`,
);

// Formatted the way Biome formats it (keys quoted only when needed).
const key = (id) => (/^[A-Za-z_$][\w$]*$/.test(id) ? id : JSON.stringify(id));
const lines = icons.map((icon) => `  ${key(icon.id)}: new URL("../icons/${icon.id}.png", import.meta.url).href,`);
writeFileSync(
  join(PACKAGE, "src/generated.ts"),
  `// Generated by scripts/update-brand-icons.mjs. Do not edit.
// Literal URLs so that bundlers (Vite) copy each icon as an asset.
export const ICON_URLS: Record<string, string> = {
${lines.join("\n")}
};
`,
);

if (failed.length) {
  console.log(`\nCould not fetch: ${failed.join(", ")}`);
  process.exitCode = 1;
}
