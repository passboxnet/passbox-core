#!/usr/bin/env node
/**
 * Builds the bundled website icons of popular sites in packages/site-icons.
 *
 * Clients show these without asking any server, and never ask the Passbox
 * server for a bundled domain (docs/architecture/item-extras.md#website-icons).
 *
 * 1. The ranking: the top domains of the Majestic Million (CC BY 3.0, see
 *    THIRD_PARTY_NOTICES.md). The default Tranco list is not used because it
 *    includes Cloudflare Radar data under CC BY-NC 4.0.
 * 2. The icons: fetched with the server's own fetcher
 *    (`cargo run -p passbox-server --example fetch-site-icons`), so the same
 *    rules apply as for icons the server fetches at run time: valid public
 *    domain names, https only, public addresses, checked redirects, 200 KB,
 *    raster images whose bytes match their type. HTTPS_PROXY is honoured.
 * 3. Scaling: decoded in a headless Chromium (the e2e package's Playwright;
 *    no image library needed), scaled to 32 and 64 px squares and encoded as
 *    WebP. Blank (fully transparent) icons are dropped.
 * 4. Output in packages/site-icons/packs: web-32.pbia (32 px, every site)
 *    and web-64.pbia (64 px, the most popular sites) as atlases for the web
 *    app, desktop and extension (src/pack.ts); mobile/site-icons-64.pbic
 *    with one WebP per site for iOS and Android (crates/client/src/site_icons.rs);
 *    manifest.json with the source, date, sizes and every bundled domain's
 *    rank and icon URL.
 *
 *   node scripts/update-site-icons.mjs                    # top 5,000 domains
 *   node scripts/update-site-icons.mjs --count 1000       # fewer
 *   node scripts/update-site-icons.mjs --reuse raw.jsonl  # re-encode a previous fetch
 *
 * Options: --count N (domains to try, default 5000), --mobile N (sites in
 * the mobile pack, default 1000), --web64 N (sites in the 64 px web atlas,
 * default 1000), --threads N (parallel fetches, default 32),
 * --list FILE|URL (a ranking CSV: Majestic Million format, or `rank,domain`
 * lines like Tranco), --quality Q (WebP quality 0-1, default 0.82),
 * --raw FILE (keep the fetched icons as JSON lines), --reuse FILE.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGE = join(ROOT, "packages/site-icons");
const PACKS = join(PACKAGE, "packs");
const MAJESTIC = "https://downloads.majestic.com/majestic_million.csv";
const SIZES = [32, 64];

const options = {
  count: 5000,
  mobile: 1000,
  web64: 1000,
  threads: 32,
  list: MAJESTIC,
  quality: 0.82,
  raw: "",
  reuse: "",
};
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const name = argv[i].replace(/^--/, "");
  if (!(name in options)) throw new Error(`unknown option ${argv[i]}`);
  const value = argv[++i];
  options[name] = typeof options[name] === "number" ? Number(value) : value;
}

const work = mkdtempSync(join(tmpdir(), "passbox-site-icons-"));

/** The ranking's top `count` domains, in rank order. */
function ranking(source, count) {
  let text;
  if (existsSync(source)) text = readFileSync(source, "utf8");
  else {
    // The list is sorted by rank: the first rows are enough.
    const bytes = count * 160 + 65_536;
    text = execFileSync("curl", ["-sSfL", "--max-time", "120", "--proto", "=https", "-r", `0-${bytes}`, source], {
      encoding: "utf8",
      maxBuffer: bytes * 2,
    });
  }
  const lines = text.split(/\r?\n/);
  const header = lines[0].split(",");
  const column = header.indexOf("Domain");
  const rows = column >= 0 ? lines.slice(1) : lines;
  const domains = [];
  const seen = new Set();
  for (const line of rows) {
    const fields = line.split(",");
    const domain = (column >= 0 ? fields[column] : fields[1])?.trim().toLowerCase().replace(/\.$/, "");
    if (!domain || seen.has(domain) || !/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(domain)) continue;
    seen.add(domain);
    domains.push(domain);
    if (domains.length >= count) break;
  }
  return domains;
}

/** Fetches icons with the server's fetcher. Returns parsed JSON lines in input order. */
function fetchIcons(domains) {
  const input = join(work, "domains.txt");
  const output = options.raw || join(work, "raw.jsonl");
  writeFileSync(input, `${domains.join("\n")}\n`);
  const stdin = openSync(input, "r");
  const stdout = openSync(output, "w");
  const result = spawnSync(
    "cargo",
    [
      "run",
      "-q",
      "--locked",
      "-p",
      "passbox-server",
      "--example",
      "fetch-site-icons",
      "--",
      "--threads",
      String(options.threads),
    ],
    { cwd: ROOT, stdio: [stdin, stdout, "inherit"], env: { SQLX_OFFLINE: "true", ...process.env } },
  );
  closeSync(stdin);
  closeSync(stdout);
  if (result.status !== 0) throw new Error(`fetch-site-icons failed (${result.status ?? result.signal})`);
  return readLines(output);
}

function readLines(file) {
  return readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

const require = createRequire(join(ROOT, "e2e/package.json"));
const { chromium } = require("@playwright/test");

/** Decodes the icons in Chromium and encodes each size as WebP. */
async function render(fetched) {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setContent("<!doctype html><title>icons</title>");
  const out = [];
  const batch = 50;
  for (let i = 0; i < fetched.length; i += batch) {
    const chunk = fetched
      .slice(i, i + batch)
      .map((f) => ({ domain: f.domain, url: `data:${f.contentType};base64,${f.bytes}` }));
    const rendered = await page.evaluate(
      async ({ chunk, sizes, quality }) => {
        /** Scales in steps of at most half, which keeps small sizes sharp. */
        function scaled(img, w, h, size) {
          const scale = Math.min(size / w, size / h);
          let source = img;
          let sw = w;
          let sh = h;
          const target = Math.max(w, h) * scale;
          while (Math.max(sw, sh) / 2 >= target) {
            const step = document.createElement("canvas");
            step.width = Math.max(1, Math.round(sw / 2));
            step.height = Math.max(1, Math.round(sh / 2));
            const sctx = step.getContext("2d");
            sctx.imageSmoothingQuality = "high";
            sctx.drawImage(source, 0, 0, step.width, step.height);
            source = step;
            sw = step.width;
            sh = step.height;
          }
          const canvas = document.createElement("canvas");
          canvas.width = size;
          canvas.height = size;
          const ctx = canvas.getContext("2d");
          ctx.imageSmoothingEnabled = true;
          ctx.imageSmoothingQuality = "high";
          const dw = Math.round(w * scale);
          const dh = Math.round(h * scale);
          ctx.drawImage(source, 0, 0, sw, sh, Math.floor((size - dw) / 2), Math.floor((size - dh) / 2), dw, dh);
          return canvas;
        }
        const results = [];
        for (const { domain, url } of chunk) {
          const img = new Image();
          img.src = url;
          try {
            await img.decode();
          } catch {
            results.push({ domain, error: "decode" });
            continue;
          }
          const w = img.naturalWidth;
          const h = img.naturalHeight;
          if (!w || !h) {
            results.push({ domain, error: "empty" });
            continue;
          }
          const result = { domain, natural: Math.min(w, h), images: {} };
          for (const size of sizes) {
            const canvas = scaled(img, w, h, size);
            if (size === sizes[sizes.length - 1]) {
              const pixels = canvas.getContext("2d").getImageData(0, 0, size, size).data;
              let visible = 0;
              for (let p = 3; p < pixels.length; p += 4) if (pixels[p] > 16) visible++;
              result.blank = visible < size * size * 0.02;
              // Mobile packs hold one WebP per icon.
              result.webp = canvas.toDataURL("image/webp", quality);
            }
            // Lossless until the atlases are encoded.
            result.images[size] = canvas.toDataURL("image/png");
          }
          results.push(result);
        }
        return results;
      },
      { chunk, sizes: SIZES, quality: options.quality },
    );
    out.push(...rendered);
    process.stderr.write(`rendered ${Math.min(i + batch, fetched.length)}/${fetched.length}\r`);
  }
  process.stderr.write("\n");
  await browser.close();
  return out;
}

const byDomain = (a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0);

/**
 * A pack of single images (crates/client/src/site_icons.rs), little endian:
 *
 *   "PBIC" | u8 version 1 | u8 size (px) | u16 0 | u32 count | u32 data offset
 *   count × ( u8 domain length | domain (ASCII) | u32 offset | u32 length ), sorted by domain
 *   image data (one WebP per icon), offsets relative to the data offset
 */
function pack(entries, size) {
  const sorted = [...entries].sort(byDomain);
  const images = sorted.map((e) => Buffer.from(e.webp.split(",")[1], "base64"));
  const indexBytes = sorted.reduce((sum, e) => sum + 1 + e.domain.length + 8, 0);
  const header = Buffer.alloc(16);
  header.write("PBIC", 0, "ascii");
  header.writeUInt8(1, 4);
  header.writeUInt8(size, 5);
  header.writeUInt32LE(sorted.length, 8);
  header.writeUInt32LE(16 + indexBytes, 12);
  const index = Buffer.alloc(indexBytes);
  let at = 0;
  let offset = 0;
  sorted.forEach((entry, i) => {
    index.writeUInt8(entry.domain.length, at);
    index.write(entry.domain, at + 1, "ascii");
    at += 1 + entry.domain.length;
    index.writeUInt32LE(offset, at);
    index.writeUInt32LE(images[i].length, at + 4);
    at += 8;
    offset += images[i].length;
  });
  return Buffer.concat([header, index, ...images]);
}

/**
 * An atlas pack (packages/site-icons/src/pack.ts): all icons in one WebP,
 * which compresses far better than one file per icon. Little endian:
 *
 *   "PBIA" | u8 version 1 | u8 tile size (px) | u16 columns | u32 count | u32 image offset
 *   count × ( u8 domain length | domain (ASCII) ), sorted by domain; the
 *   n-th domain's tile is at column n % columns, row n / columns
 *   the atlas (WebP)
 */
async function atlas(page, entries, size) {
  const sorted = [...entries].sort(byDomain);
  const columns = Math.min(Math.floor(8192 / size), Math.max(1, Math.ceil(Math.sqrt(sorted.length))));
  const image = await page.evaluate(
    async ({ urls, size, columns, quality }) => {
      const rows = Math.ceil(urls.length / columns);
      const canvas = document.createElement("canvas");
      canvas.width = columns * size;
      canvas.height = rows * size;
      const ctx = canvas.getContext("2d");
      for (let i = 0; i < urls.length; i++) {
        const img = new Image();
        img.src = urls[i];
        await img.decode();
        ctx.drawImage(img, (i % columns) * size, Math.floor(i / columns) * size);
      }
      return canvas.toDataURL("image/webp", quality);
    },
    { urls: sorted.map((e) => e.images[size]), size, columns, quality: options.quality },
  );
  const webp = Buffer.from(image.split(",")[1], "base64");
  const indexBytes = sorted.reduce((sum, e) => sum + 1 + e.domain.length, 0);
  const header = Buffer.alloc(16);
  header.write("PBIA", 0, "ascii");
  header.writeUInt8(1, 4);
  header.writeUInt8(size, 5);
  header.writeUInt16LE(columns, 6);
  header.writeUInt32LE(sorted.length, 8);
  header.writeUInt32LE(16 + indexBytes, 12);
  const index = Buffer.alloc(indexBytes);
  let at = 0;
  for (const entry of sorted) {
    index.writeUInt8(entry.domain.length, at);
    index.write(entry.domain, at + 1, "ascii");
    at += 1 + entry.domain.length;
  }
  return Buffer.concat([header, index, webp]);
}

const today = new Date().toISOString().slice(0, 10);
const domains = ranking(options.list, options.count);
console.log(`ranking: ${domains.length} domains from ${options.list}`);
const rank = new Map(domains.map((d, i) => [d, i + 1]));
const fetched = options.reuse ? readLines(options.reuse) : fetchIcons(domains);
const hits = fetched.filter((f) => !f.miss && f.bytes && rank.has(f.domain));
console.log(`fetched: ${hits.length} icons, ${fetched.length - hits.length} without`);
const rendered = (await render(hits)).filter((r) => !r.error && !r.blank && r.images);
const source = new Map(hits.map((h) => [h.domain, h.source]));
rendered.sort((a, b) => rank.get(a.domain) - rank.get(b.domain));
console.log(`usable: ${rendered.length}`);

mkdirSync(PACKS, { recursive: true });
const files = {};
const write = (name, size, icons, bytes) => {
  writeFileSync(join(PACKS, name), bytes);
  files[name] = { size, icons, bytes: bytes.length };
};
{
  // Web, desktop and extension: 32 px for every site, 64 px (screens with
  // more than one pixel per point) for the most popular ones.
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setContent("<!doctype html><title>atlas</title>");
  write("web-32.pbia", 32, rendered.length, await atlas(page, rendered, 32));
  const top = rendered.slice(0, options.web64);
  write("web-64.pbia", 64, top.length, await atlas(page, top, 64));
  await browser.close();
}
const mobile = rendered.slice(0, options.mobile);
{
  // Its own directory: the Android app adds it as an asset directory.
  mkdirSync(join(PACKAGE, "mobile"), { recursive: true });
  const bytes = pack(mobile, 64);
  writeFileSync(join(PACKAGE, "mobile/site-icons-64.pbic"), bytes);
  files["mobile/site-icons-64.pbic"] = { size: 64, icons: mobile.length, bytes: bytes.length };
}
const listName = options.list === MAJESTIC ? "Majestic Million" : options.list;
const manifest = {
  $comment: "Generated by scripts/update-site-icons.mjs. Do not edit.",
  generated: today,
  ranking: {
    name: listName,
    url: options.list,
    license: options.list === MAJESTIC ? "CC BY 3.0 (https://creativecommons.org/licenses/by/3.0/)" : "see source",
    downloaded: today,
    domainsTried: domains.length,
  },
  files,
  // Bundled sites: [domain, rank, icon URL].
  sites: rendered.map((r) => [r.domain, rank.get(r.domain), source.get(r.domain) ?? null]),
};
writeFileSync(join(PACKAGE, "manifest.json"), `${JSON.stringify(manifest, null, 1)}\n`);
rmSync(work, { recursive: true, force: true });
for (const [name, info] of Object.entries(files)) {
  console.log(`${name.padEnd(18)} ${String(info.icons).padStart(5)} icons  ${(info.bytes / 1024).toFixed(0)} KB`);
}
