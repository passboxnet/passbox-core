#!/usr/bin/env node
// Generates every Passbox logo, app icon and icon-family asset from SVG
// sources, so all platforms show the same mark (docs/design/brand.md).
//
//   node scripts/generate-brand-assets.mjs
//
// Sources: the mark geometry below, the signature gradient and brand colors in
// packages/ui/tokens/tokens.json and the icon list in packages/ui/brand/icons.json
// (Lucide outlines from lucide-react). Rasterizes with Playwright's Chromium
// (installed for the e2e tests). Writes:
//
//   packages/ui/brand/*.svg                       mark, app icon, glyph, desktop icon (sources)
//   packages/ui/brand/png/                        email header logo, Play Store icon, previews
//   apps/ios/Passbox/Assets.xcassets/AppIcon.appiconset   light, dark and tinted 1024 px
//   apps/ios/Shared/Icons.xcassets + PassboxIcon.swift    icon family (template SVGs)
//   apps/android/app/src/main/res/drawable/ic_launcher_*.xml, pb_icon_*.xml
//   apps/android/.../ui/theme/PassboxIcons.kt
//   apps/desktop/assets/icon.svg, apps/desktop/src-tauri/icons/*
//   apps/extension/public/icons/icon-{16,32,48,128}.png
//   apps/web/public, apps/website/public: favicon.svg, favicon.ico, apple-touch-icon.png, icon-512.png

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deflateSync, inflateSync } from "node:zlib";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tokens = JSON.parse(readFileSync(join(root, "packages/ui/tokens/tokens.json"), "utf8"));
const iconList = JSON.parse(readFileSync(join(root, "packages/ui/brand/icons.json"), "utf8")).icons;
const requireFromUi = createRequire(join(root, "packages/ui/package.json"));
const requireFromE2e = createRequire(join(root, "e2e/package.json"));

const write = (path, data) => {
  const file = join(root, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, data);
  console.log(`wrote ${path}`);
};

// ---------------------------------------------------------------- colors

function oklchToHex(value) {
  const m = value.match(/oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
  const [l, c, h] = m.slice(1).map(Number);
  const rad = (h * Math.PI) / 180;
  const a = c * Math.cos(rad);
  const b = c * Math.sin(rad);
  const l1 = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m1 = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s1 = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const lin = [
    4.0767416621 * l1 - 3.3077115913 * m1 + 0.2309699292 * s1,
    -1.2684380046 * l1 + 2.6097574011 * m1 - 0.3413193965 * s1,
    -0.0041960863 * l1 - 0.7034186147 * m1 + 1.707614701 * s1,
  ];
  const enc = (x) => (x <= 0.0031308 ? 12.92 * x : 1.055 * x ** (1 / 2.4) - 0.055);
  return `#${lin
    .map((x) => Math.round(Math.min(1, Math.max(0, enc(Math.min(1, Math.max(0, x))))) * 255))
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase()}`;
}

const signature = tokens.gradient.signature.stops.map(([at, c]) => [at, oklchToHex(c)]);
/** Named brand colors: Solar Silk glyph on a Nocturnal Marina tile, a soft Sky glow. */
const SOLAR = oklchToHex(tokens.palette.solar.value);
const SKY = oklchToHex(tokens.palette.sky.value);
const MARINA_LIP = oklchToHex(tokens.palette["marina-lip"].value);
const wordmark = { light: oklchToHex(tokens.color.text.light), dark: oklchToHex(tokens.color.text.dark) };

// ---------------------------------------------------------------- the mark (32-unit grid)

/** The keyhole: a circle over a tapered stem with rounded feet. */
const GLYPH = {
  circle: { cx: 16, cy: 13.4, r: 4.2 },
  stem: "M14.2 16.2h3.6l1.1 6.9a.8.8 0 0 1-.8.9h-4.2a.8.8 0 0 1-.8-.9z",
};

const glyphSvg = (fill) =>
  `<circle cx="${GLYPH.circle.cx}" cy="${GLYPH.circle.cy}" r="${GLYPH.circle.r}" fill="${fill}"/><path d="${GLYPH.stem}" fill="${fill}"/>`;

const gradientDefs = (id) => `<linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1">${signature
  .map(([at, c]) => `<stop offset="${at}" stop-color="${c}"/>`)
  .join("")}</linearGradient>
    <radialGradient id="${id}-glow" cx="0.22" cy="0.12" r="0.75"><stop offset="0" stop-color="${SKY}" stop-opacity="0.38"/><stop offset="1" stop-color="${SKY}" stop-opacity="0"/></radialGradient>`;

/** The mark on its rounded tile (28 % radius). `stroke`: the thin inner highlight (off at 16 px). */
function markSvg({ size = 32, stroke = true, title = true } = {}) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="${size}" height="${size}">${title ? "<title>Passbox</title>" : ""}
  <defs>${gradientDefs("pb")}</defs>
  <rect width="32" height="32" rx="9" fill="url(#pb)"/>
  <rect width="32" height="32" rx="9" fill="url(#pb-glow)"/>
  ${stroke ? '<rect x="0.5" y="0.5" width="31" height="31" rx="8.5" fill="none" stroke="#fff" stroke-opacity="0.14"/>' : ""}
  ${glyphSvg(SOLAR)}
</svg>
`;
}

/** Full-bleed square (iOS, apple-touch-icon, Play Store): the platform rounds the corners. */
function appIconSvg(variant = "light") {
  const glyph = (fill) => `<g transform="translate(96 96) scale(26)">${glyphSvg(fill)}</g>`;
  if (variant === "dark") {
    // iOS dark icons: no background (the system draws one); the Solar glyph alone.
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024"><title>Passbox</title>
  <g transform="translate(96 96) scale(26)">${glyphSvg(SOLAR)}</g>
</svg>
`;
  }
  if (variant === "tinted") {
    // iOS tinted icons: grayscale on black; the system tints it.
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024"><title>Passbox</title>
  <rect width="1024" height="1024" fill="#000"/>
  ${glyph("#fff")}
</svg>
`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024"><title>Passbox</title>
  <defs>${gradientDefs("pb")}</defs>
  <rect width="1024" height="1024" fill="url(#pb)"/>
  <rect width="1024" height="1024" fill="url(#pb-glow)"/>
  ${glyph(SOLAR)}
</svg>
`;
}

/** Desktop (macOS grid: 824 px tile on a 1024 px canvas, soft shadow; also used for Windows and Linux). */
function desktopIconSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
  <title>Passbox</title>
  <!-- Generated by scripts/generate-brand-assets.mjs. The Passbox mark on the macOS icon grid. -->
  <defs>${gradientDefs("pb")}
    <filter id="shadow" x="-10%" y="-10%" width="120%" height="125%"><feDropShadow dx="0" dy="0.45" stdDeviation="0.55" flood-color="${MARINA_LIP}" flood-opacity="0.45"/></filter>
  </defs>
  <g transform="translate(100 100) scale(25.75)">
    <rect width="32" height="32" rx="7.2" fill="url(#pb)" filter="url(#shadow)"/>
    <rect width="32" height="32" rx="7.2" fill="url(#pb-glow)"/>
    <rect x="0.25" y="0.25" width="31.5" height="31.5" rx="6.95" fill="none" stroke="#fff" stroke-opacity="0.16" stroke-width="0.5"/>
    ${glyphSvg(SOLAR)}
  </g>
</svg>
`;
}

// ---------------------------------------------------------------- PNG helpers

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "ascii");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, "ascii"), data])), 8 + data.length);
  return out;
};

/** Re-encodes an 8-bit RGBA PNG (as Chromium writes it) without the alpha channel (App Store icons must be opaque). */
function dropAlpha(png) {
  let offset = 8;
  let width = 0;
  let height = 0;
  const idat = [];
  while (offset < png.length) {
    const length = png.readUInt32BE(offset);
    const type = png.toString("ascii", offset + 4, offset + 8);
    const data = png.subarray(offset + 8, offset + 8 + length);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      if (data[8] === 8 && data[9] === 2) return png; // already opaque RGB
      if (data[8] !== 8 || data[9] !== 6) throw new Error("expected 8-bit RGB or RGBA PNG");
    } else if (type === "IDAT") idat.push(data);
    offset += 12 + length;
  }
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * 4;
  const rgba = Buffer.alloc(height * stride);
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    const out = rgba.subarray(y * stride, (y + 1) * stride);
    for (let x = 0; x < stride; x++) {
      const a = x >= 4 ? out[x - 4] : 0;
      const b = prev[x];
      const c = x >= 4 ? prev[x - 4] : 0;
      let v = line[x];
      if (filter === 1) v += a;
      else if (filter === 2) v += b;
      else if (filter === 3) v += (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      out[x] = v & 0xff;
    }
    prev = out;
  }
  const rgb = Buffer.alloc(height * (width * 3 + 1));
  for (let y = 0; y < height; y++) {
    rgb[y * (width * 3 + 1)] = 0;
    for (let x = 0; x < width; x++) {
      const src = y * stride + x * 4;
      const dst = y * (width * 3 + 1) + 1 + x * 3;
      rgba.copy(rgb, dst, src, src + 3);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(rgb, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/** Windows .ico with PNG entries. */
function ico(pngs) {
  const header = Buffer.alloc(6 + 16 * pngs.length);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(pngs.length, 4);
  let offset = header.length;
  pngs.forEach(({ size, data }, i) => {
    const e = 6 + 16 * i;
    header[e] = size >= 256 ? 0 : size;
    header[e + 1] = size >= 256 ? 0 : size;
    header.writeUInt16LE(1, e + 4);
    header.writeUInt16LE(32, e + 6);
    header.writeUInt32LE(data.length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...pngs.map((p) => p.data)]);
}

/** macOS .icns with PNG entries. */
function icns(entries) {
  const parts = entries.map(([type, data]) => {
    const head = Buffer.alloc(8);
    head.write(type, 0, "ascii");
    head.writeUInt32BE(data.length + 8, 4);
    return Buffer.concat([head, data]);
  });
  const head = Buffer.alloc(8);
  head.write("icns", 0, "ascii");
  head.writeUInt32BE(8 + parts.reduce((n, p) => n + p.length, 0), 4);
  return Buffer.concat([head, ...parts]);
}

// ---------------------------------------------------------------- rendering

const { chromium } = requireFromE2e("playwright");
const browser = await chromium.launch();
const page = await browser.newPage();

async function render(svg, size, { padding = 0, background = "transparent" } = {}) {
  await page.setViewportSize({ width: size, height: size });
  const inner = size - 2 * padding;
  const src = `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;
  await page.setContent(
    `<html><body style="margin:0;background:${background}"><img src="${src}" style="display:block;margin:${padding}px;width:${inner}px;height:${inner}px"></body></html>`,
  );
  await page.waitForFunction(() => document.images[0]?.complete);
  return page.screenshot({ omitBackground: background === "transparent", type: "png" });
}

const fontData = (pkg, file) =>
  readFileSync(join(dirname(requireFromUi.resolve(`${pkg}/package.json`)), "files", file)).toString("base64");

async function renderHtml(html, width, height, scale) {
  const context = await browser.newContext({ deviceScaleFactor: scale, viewport: { width, height } });
  const p = await context.newPage();
  await p.setContent(html);
  await p.evaluate(() => document.fonts.ready);
  const png = await p.screenshot({ omitBackground: true, type: "png" });
  await context.close();
  return png;
}

// ---------------------------------------------------------------- sources

const mark = markSvg();
write("packages/ui/brand/mark.svg", mark);
write("packages/ui/brand/mark-small.svg", markSvg({ stroke: false }));
write("packages/ui/brand/app-icon.svg", appIconSvg("light"));
write("packages/ui/brand/app-icon-dark.svg", appIconSvg("dark"));
write("packages/ui/brand/app-icon-tinted.svg", appIconSvg("tinted"));
write(
  "packages/ui/brand/glyph.svg",
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><title>Passbox</title>${glyphSvg("currentColor")}</svg>\n`,
);
const desktop = desktopIconSvg();
write("apps/desktop/assets/icon.svg", desktop);

// ---------------------------------------------------------------- iOS app icon

const iosIcons = "apps/ios/Passbox/Assets.xcassets/AppIcon.appiconset";
write(`${iosIcons}/AppIcon.png`, dropAlpha(await render(appIconSvg("light"), 1024, { background: "#000" })));
write(`${iosIcons}/AppIcon-Dark.png`, await render(appIconSvg("dark"), 1024));
write(`${iosIcons}/AppIcon-Tinted.png`, dropAlpha(await render(appIconSvg("tinted"), 1024, { background: "#000" })));
write(
  `${iosIcons}/Contents.json`,
  `${JSON.stringify(
    {
      images: [
        { filename: "AppIcon.png", idiom: "universal", platform: "ios", size: "1024x1024" },
        {
          appearances: [{ appearance: "luminosity", value: "dark" }],
          filename: "AppIcon-Dark.png",
          idiom: "universal",
          platform: "ios",
          size: "1024x1024",
        },
        {
          appearances: [{ appearance: "luminosity", value: "tinted" }],
          filename: "AppIcon-Tinted.png",
          idiom: "universal",
          platform: "ios",
          size: "1024x1024",
        },
      ],
      info: { author: "xcode", version: 1 },
    },
    null,
    2,
  )}\n`,
);

// ---------------------------------------------------------------- Android adaptive icon

const res = "apps/android/app/src/main/res";
// The glyph in the 108 dp adaptive canvas: centred, about 32 dp tall (inside the 66 dp safe zone).
const androidGlyph = (fill) => `    <group
        android:translateX="18"
        android:translateY="18"
        android:scaleX="2.25"
        android:scaleY="2.25">
        <path
            android:fillColor="${fill}"
            android:pathData="M${GLYPH.circle.cx - GLYPH.circle.r},${GLYPH.circle.cy}a${GLYPH.circle.r},${GLYPH.circle.r} 0,1 0,${2 * GLYPH.circle.r},0a${GLYPH.circle.r},${GLYPH.circle.r} 0,1 0,${-2 * GLYPH.circle.r},0z" />
        <path
            android:fillColor="${fill}"
            android:pathData="${GLYPH.stem}" />
    </group>`;
const vectorHead = (comment) => `<?xml version="1.0" encoding="utf-8"?>
<!-- ${comment} Generated by scripts/generate-brand-assets.mjs. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:aapt="http://schemas.android.com/aapt"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">`;
write(
  `${res}/drawable/ic_launcher_foreground.xml`,
  `${vectorHead("Passbox keyhole on the adaptive icon.").replace('\n    xmlns:aapt="http://schemas.android.com/aapt"', "")}
${androidGlyph(`#${SOLAR.slice(1)}`)}
</vector>
`,
);
write(
  `${res}/drawable/ic_launcher_monochrome.xml`,
  `${vectorHead("Themed (monochrome) launcher icon: the system tints the glyph.").replace('\n    xmlns:aapt="http://schemas.android.com/aapt"', "")}
${androidGlyph("#FFFFFFFF")}
</vector>
`,
);
write(
  `${res}/drawable/ic_launcher_background.xml`,
  `${vectorHead("Signature gradient behind the adaptive icon.")}
    <path android:pathData="M0,0h108v108h-108z">
        <aapt:attr name="android:fillColor">
            <gradient
                android:type="linear"
                android:startX="0"
                android:startY="0"
                android:endX="108"
                android:endY="108">
${signature.map(([at, c]) => `                <item android:offset="${at}" android:color="#FF${c.slice(1)}" />`).join("\n")}
            </gradient>
        </aapt:attr>
    </path>
    <path android:pathData="M0,0h108v108h-108z">
        <aapt:attr name="android:fillColor">
            <gradient
                android:type="radial"
                android:centerX="24"
                android:centerY="13"
                android:gradientRadius="81">
                <item android:offset="0" android:color="#61${SKY.slice(1)}" />
                <item android:offset="1" android:color="#00${SKY.slice(1)}" />
            </gradient>
        </aapt:attr>
    </path>
</vector>
`,
);
write(
  `${res}/mipmap-anydpi-v26/ic_launcher.xml`,
  `<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by scripts/generate-brand-assets.mjs. -->
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@drawable/ic_launcher_background" />
    <foreground android:drawable="@drawable/ic_launcher_foreground" />
    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />
</adaptive-icon>
`,
);
write("apps/android/app/src/main/ic_launcher-playstore.png", dropAlpha(await render(appIconSvg("light"), 512)));

// ---------------------------------------------------------------- desktop (Tauri)

const tauri = "apps/desktop/src-tauri/icons";
const desktopPng = {};
for (const size of [16, 30, 32, 44, 64, 71, 89, 107, 128, 142, 150, 256, 284, 310, 512, 1024]) {
  desktopPng[size] = await render(size <= 32 ? markSvg({ size, stroke: false }) : desktop, size);
}
write(`${tauri}/32x32.png`, desktopPng[32]);
write(`${tauri}/128x128.png`, desktopPng[128]);
write(`${tauri}/128x128@2x.png`, desktopPng[256]);
write(`${tauri}/icon.png`, desktopPng[512]);
for (const size of [30, 44, 71, 89, 107, 142, 150, 284, 310])
  write(`${tauri}/Square${size}x${size}Logo.png`, desktopPng[size]);
write(`${tauri}/StoreLogo.png`, await render(desktop, 50));
write(`${tauri}/icon.ico`, ico([16, 32, 64, 128, 256].map((size) => ({ size, data: desktopPng[size] }))));
write(
  `${tauri}/icon.icns`,
  icns([
    ["icp4", desktopPng[16]],
    ["icp5", desktopPng[32]],
    ["icp6", desktopPng[64]],
    ["ic07", desktopPng[128]],
    ["ic08", desktopPng[256]],
    ["ic09", desktopPng[512]],
    ["ic10", desktopPng[1024]],
    ["ic11", desktopPng[32]],
    ["ic12", desktopPng[64]],
    ["ic13", desktopPng[256]],
    ["ic14", desktopPng[512]],
  ]),
);

// ---------------------------------------------------------------- browser extension

for (const size of [16, 32, 48, 128]) {
  // Chrome shows 128 px icons at 96 px with transparent padding.
  const padding = size === 128 ? 16 : size === 48 ? 2 : 0;
  write(
    `apps/extension/public/icons/icon-${size}.png`,
    await render(markSvg({ size, stroke: size >= 48 }), size, { padding }),
  );
}

// ---------------------------------------------------------------- web and website

const favicon16 = await render(markSvg({ size: 16, stroke: false }), 16);
const favicon32 = await render(markSvg({ size: 32, stroke: false }), 32);
const appleTouch = dropAlpha(await render(appIconSvg("light"), 180));
const icon512 = await render(mark, 512);
for (const app of ["apps/web/public", "apps/website/public"]) {
  write(`${app}/favicon.svg`, markSvg({ stroke: false }));
  write(
    `${app}/favicon.ico`,
    ico([
      { size: 16, data: favicon16 },
      { size: 32, data: favicon32 },
    ]),
  );
  write(`${app}/apple-touch-icon.png`, appleTouch);
  write(`${app}/icon-512.png`, icon512);
}

// ---------------------------------------------------------------- email header logo and previews

const sansWoff2 = fontData("@fontsource-variable/plus-jakarta-sans", "plus-jakarta-sans-latin-wght-normal.woff2");
const lockup = (color) => `<html><head><style>
@font-face { font-family: PJS; src: url(data:font/woff2;base64,${sansWoff2}) format("woff2"); font-weight: 200 800; }
body { margin: 0; }
.l { display: flex; align-items: center; gap: 12px; height: 48px; padding: 0 2px; font: 700 26px/1 PJS; letter-spacing: -0.02em; color: ${color}; }
</style></head><body><div class="l"><img src="data:image/svg+xml;base64,${Buffer.from(markSvg({ size: 40 })).toString("base64")}" width="40" height="40">Passbox</div></body></html>`;
write("packages/ui/brand/png/email-logo@2x.png", await renderHtml(lockup(wordmark.light), 164, 48, 2));
write("packages/ui/brand/png/email-logo-dark@2x.png", await renderHtml(lockup(wordmark.dark), 164, 48, 2));
write(
  "packages/ui/brand/png/app-icon-1024.png",
  dropAlpha(await render(appIconSvg("light"), 1024, { background: "#000" })),
);

await browser.close();

// ---------------------------------------------------------------- icon family

const lucideDir = dirname(requireFromUi.resolve("lucide-react/package.json"));
const icons = [];
for (const name of iconList) {
  let file = join(lucideDir, "dist/esm/icons", `${name}.mjs`);
  let module = await import(pathToFileURL(file).href);
  // Renamed icons are re-exports of their new name.
  const target = !module.__iconData && readFileSync(file, "utf8").match(/from '\.\/([\w-]+)\.mjs'/);
  if (target) {
    file = join(lucideDir, "dist/esm/icons", `${target[1]}.mjs`);
    module = await import(pathToFileURL(file).href);
  }
  if (!module.__iconData) throw new Error(`lucide-react has no icon data for "${name}"`);
  icons.push({ name, node: module.__iconData.node });
}

const attrs = (a) =>
  Object.entries(a)
    .filter(([k]) => k !== "key")
    .map(([k, v]) => `${k}="${v === "currentColor" ? "#000" : v}"`)
    .join(" ");
const svgOf = (node, color = "#000", title = "") =>
  `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${title ? `<title>${title}</title>` : ""}${node
    .map(([tag, a]) => `<${tag} ${attrs(a)}/>`)
    .join("")}</svg>\n`;

/** SVG element → VectorDrawable path data. */
function pathData(tag, a) {
  const n = (k, d = 0) => Number(a[k] ?? d);
  switch (tag) {
    case "path":
      return a.d;
    case "circle":
    case "ellipse": {
      const rx = tag === "circle" ? n("r") : n("rx");
      const ry = tag === "circle" ? n("r") : n("ry");
      return `M${n("cx") - rx},${n("cy")}a${rx},${ry} 0 1,0 ${2 * rx},0a${rx},${ry} 0 1,0 ${-2 * rx},0z`;
    }
    case "rect": {
      const [x, y, w, h] = [n("x"), n("y"), n("width"), n("height")];
      const r = Math.min(n("rx", a.ry ?? 0), w / 2, h / 2);
      if (!r) return `M${x},${y}h${w}v${h}h${-w}z`;
      return `M${x + r},${y}h${w - 2 * r}a${r},${r} 0 0 1 ${r},${r}v${h - 2 * r}a${r},${r} 0 0 1 ${-r},${r}h${-(w - 2 * r)}a${r},${r} 0 0 1 ${-r},${-r}v${-(h - 2 * r)}a${r},${r} 0 0 1 ${r},${-r}z`;
    }
    case "line":
      return `M${a.x1},${a.y1}L${a.x2},${a.y2}`;
    case "polyline":
    case "polygon": {
      const pts = a.points.trim().split(/[\s,]+/);
      let d = `M${pts[0]},${pts[1]}`;
      for (let i = 2; i < pts.length; i += 2) d += `L${pts[i]},${pts[i + 1]}`;
      return tag === "polygon" ? `${d}z` : d;
    }
    default:
      throw new Error(`unsupported SVG element ${tag}`);
  }
}

const camel = (s) => s.replace(/-(\w)/g, (_, c) => c.toUpperCase()).replace(/^(\d)/, "i$1");
const pascal = (s) => camel(s).replace(/^\w/, (c) => c.toUpperCase());
const snake = (s) => s.replace(/-/g, "_");

// iOS: an asset catalog of template SVGs (vector, tinted with foregroundStyle) and a Swift enum.
const catalog = "apps/ios/Shared/Icons.xcassets";
rmSync(join(root, catalog), { recursive: true, force: true });
write(`${catalog}/Contents.json`, `${JSON.stringify({ info: { author: "xcode", version: 1 } }, null, 2)}\n`);
for (const { name, node } of icons) {
  write(`${catalog}/${name}.imageset/${name}.svg`, svgOf(node, "#000", name));
  write(
    `${catalog}/${name}.imageset/Contents.json`,
    `${JSON.stringify(
      {
        images: [{ filename: `${name}.svg`, idiom: "universal" }],
        info: { author: "xcode", version: 1 },
        properties: { "preserves-vector-representation": true, "template-rendering-intent": "template" },
      },
      null,
      2,
    )}\n`,
  );
}
write(
  "apps/ios/Shared/PassboxIcon.swift",
  `// Generated by scripts/generate-brand-assets.mjs from packages/ui/brand/icons.json. Do not edit.
//
// The Passbox icon family (Lucide outlines, ISC/MIT; see THIRD_PARTY_NOTICES.md),
// the same icons as the web app. Template images: color them with
// foregroundStyle. Size them like SF Symbols with .frame or .font-relative
// sizing in a Label; they are 24 × 24 pt vectors with a 2 pt stroke.

import SwiftUI

enum PassboxIcon: String, CaseIterable, Sendable {
${icons.map(({ name }) => `    case ${camel(name)} = "${name}"`).join("\n")}

    var image: Image { Image(rawValue).renderingMode(.template) }
}
`,
);

// Android: vector drawables and a Kotlin lookup.
const drawable = `${res}/drawable`;
for (const { name, node } of icons) {
  const paths = node
    .map(([tag, a]) => {
      const filled = a.fill === "currentColor";
      return `    <path
        android:fillColor="${filled ? "#FF000000" : "#00000000"}"
        android:strokeColor="#FF000000"
        android:strokeWidth="2"
        android:strokeLineCap="round"
        android:strokeLineJoin="round"
        android:pathData="${pathData(tag, a)}" />`;
    })
    .join("\n");
  write(
    `${drawable}/pb_icon_${snake(name)}.xml`,
    `<?xml version="1.0" encoding="utf-8"?>
<!-- Lucide "${name}" (ISC). Generated by scripts/generate-brand-assets.mjs. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
${paths}
</vector>
`,
  );
}
write(
  "apps/android/app/src/main/java/dev/passbox/android/ui/theme/PassboxIcons.kt",
  `// Generated by scripts/generate-brand-assets.mjs from packages/ui/brand/icons.json. Do not edit.
//
// The Passbox icon family (Lucide outlines, ISC/MIT; see THIRD_PARTY_NOTICES.md),
// the same icons as the web app: 24 dp vectors with a 2 dp stroke. Use with
// Icon(painterResource(PassboxIcons.KeyRound), contentDescription = …).

package dev.passbox.android.ui.theme

import androidx.annotation.DrawableRes
import dev.passbox.android.R

object PassboxIcons {
${icons.map(({ name }) => `    @DrawableRes val ${pascal(name)} = R.drawable.pb_icon_${snake(name)}`).join("\n")}

    /** Every icon by its Lucide name, for previews and the design board. */
    val all: Map<String, Int> = mapOf(
${icons.map(({ name }) => `        "${name}" to ${pascal(name)},`).join("\n")}
    )
}
`,
);

// ---------------------------------------------------------------- design board

// The board is one self-contained file: fonts, mark and icons are inlined.
const boardPath = join(root, "docs/design/board.html");
let board = readFileSync(boardPath, "utf8");
function region(marker, body, comment = ["<!--", "-->"]) {
  const start = `${comment[0]} @generated ${marker}:start ${comment[1]}`;
  const end = `${comment[0]} @generated ${marker}:end ${comment[1]}`;
  const i = board.indexOf(start);
  const j = board.indexOf(end);
  if (i < 0 || j < i) throw new Error(`docs/design/board.html: markers for "${marker}" not found`);
  board = `${board.slice(0, i + start.length)}\n${body}\n${board.slice(j)}`;
}
const monoWoff2 = fontData("@fontsource-variable/jetbrains-mono", "jetbrains-mono-latin-wght-normal.woff2");
region(
  "fonts",
  `@font-face { font-family: "Plus Jakarta Sans Variable"; font-weight: 200 800; font-display: block; src: url(data:font/woff2;base64,${sansWoff2}) format("woff2"); }
@font-face { font-family: "JetBrains Mono Variable"; font-weight: 100 800; font-display: block; src: url(data:font/woff2;base64,${monoWoff2}) format("woff2"); }`,
  ["/*", "*/"],
);
region(
  "icons",
  icons
    .map(
      ({ name, node }) =>
        `<figure class="icon-cell" data-name="${name}">${svgOf(node, "currentColor").trim()}<figcaption>${name}</figcaption></figure>`,
    )
    .join("\n"),
);
region(
  "mark",
  `<template id="pb-mark">${markSvg({ size: 32, title: false }).trim()}</template>
<template id="pb-app-icon">${appIconSvg("light").trim()}</template>
<template id="pb-app-icon-dark">${appIconSvg("dark").trim()}</template>
<template id="pb-desktop-icon">${desktop.trim()}</template>`,
);
writeFileSync(boardPath, board);
console.log("wrote docs/design/board.html (fonts, mark, icons)");
