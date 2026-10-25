#!/usr/bin/env node
// Generates the Passbox design tokens for every platform from one source,
// packages/ui/tokens/tokens.json:
//
//   packages/ui/src/tokens.css                    (regions between @generated markers)
//   apps/ios/Shared/DesignTokens.swift            (whole file)
//   apps/android/.../ui/theme/Tokens.kt           (whole file)
//   docs/design/system.md                         (token tables between markers)
//   docs/design/board.html                        (CSS variables between markers)
//
//   node scripts/generate-design-tokens.mjs           write the files
//   node scripts/generate-design-tokens.mjs --check   fail if a file is stale,
//                                                    a color leaves sRGB or a
//                                                    contrast pair misses its target
//
// Colors are OKLCH in the source. CSS keeps OKLCH; native files get sRGB hex.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tokens = JSON.parse(readFileSync(join(root, "packages/ui/tokens/tokens.json"), "utf8"));
const check = process.argv.includes("--check");
const problems = new Set();

// ---------------------------------------------------------------- color math

function parseOklch(value) {
  const m = value.match(/^oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(?:\/\s*([\d.]+)\s*)?\)$/);
  if (!m) throw new Error(`not an oklch() color: ${value}`);
  return { l: Number(m[1]), c: Number(m[2]), h: Number(m[3]), alpha: m[4] === undefined ? 1 : Number(m[4]) };
}

function oklchToLinearSrgb({ l, c, h }) {
  const rad = (h * Math.PI) / 180;
  const a = c * Math.cos(rad);
  const b = c * Math.sin(rad);
  const l1 = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m1 = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s1 = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return [
    4.0767416621 * l1 - 3.3077115913 * m1 + 0.2309699292 * s1,
    -1.2684380046 * l1 + 2.6097574011 * m1 - 0.3413193965 * s1,
    -0.0041960863 * l1 - 0.7034186147 * m1 + 1.707614701 * s1,
  ];
}

const encode = (x) => (x <= 0.0031308 ? 12.92 * x : 1.055 * x ** (1 / 2.4) - 0.055);
const clamp01 = (x) => Math.min(1, Math.max(0, x));

function toSrgb(value, name) {
  const color = parseOklch(value);
  const linear = oklchToLinearSrgb(color);
  if (linear.some((x) => x < -0.002 || x > 1.002)) problems.add(`${name}: ${value} is outside sRGB`);
  const rgb = linear.map((x) => Math.round(clamp01(encode(clamp01(x))) * 255));
  return { rgb, alpha: color.alpha, linear: linear.map(clamp01) };
}

const hex2 = (n) => n.toString(16).padStart(2, "0").toUpperCase();
const hexRgb = (value, name) => `#${toSrgb(value, name).rgb.map(hex2).join("")}`;
const argb = (value, name) => {
  const { rgb, alpha } = toSrgb(value, name);
  return `0x${hex2(Math.round(alpha * 255))}${rgb.map(hex2).join("")}`;
};

/** Relative luminance; translucent colors are composited over `under` first. */
function luminance(value, under) {
  const { linear, alpha } = toSrgb(value, "contrast");
  let lin = linear;
  if (alpha < 1 && under) {
    const base = toSrgb(under, "contrast").linear;
    // Composite in gamma space, as browsers do.
    const enc = linear.map(encode);
    const encBase = base.map(encode);
    lin = enc
      .map((x, i) => x * alpha + encBase[i] * (1 - alpha))
      .map((x) => (x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
  }
  return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
}

function contrastRatio(fg, bg) {
  const a = luminance(fg, bg);
  const b = luminance(bg);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

// ---------------------------------------------------------------- checks

const themes = ["light", "dark"];
const colorNames = Object.keys(tokens.color);
const contrastResults = [];
for (const [fg, bg, target] of tokens.contrast) {
  for (const theme of themes) {
    const ratio = contrastRatio(tokens.color[fg][theme], tokens.color[bg][theme]);
    contrastResults.push({ fg, bg, theme, ratio, target });
    if (ratio + 1e-9 < target) problems.add(`contrast ${fg} on ${bg} (${theme}): ${ratio.toFixed(2)} < ${target}`);
  }
}
for (const name of colorNames) for (const theme of themes) toSrgb(tokens.color[name][theme], `${name} (${theme})`);
for (const [k, v] of Object.entries(tokens.brand)) toSrgb(v, `brand-${k}`);
for (const [k, v] of Object.entries(tokens.tag)) toSrgb(v, `tag-${k}`);

// ---------------------------------------------------------------- helpers

const camel = (s) => s.replace(/[-.](\w)/g, (_, c) => c.toUpperCase());
const pascal = (s) => camel(s).replace(/^\w/, (c) => c.toUpperCase());
const rem = (px) => `${+(px / 16).toFixed(4)}rem`;
const num = (n) => `${+n.toFixed(4)}`;
const bezier = (p) => `cubic-bezier(${p.join(", ")})`;
const GENERATED = "Generated by scripts/generate-design-tokens.mjs from packages/ui/tokens/tokens.json. Do not edit.";

/** Tailwind color names that read from another token (backward-compatible and spec names). */
const colorAliases = {
  "surface-1": "surface",
  "surface-2": "surface-raised",
  "surface-3": "surface-overlay",
  "text-primary": "text",
  "text-secondary": "text-muted",
  "text-tertiary": "text-subtle",
};

/** `text-<name>` reads these instead of the fill color (fills need white text; text needs contrast to the canvas). */
const textColorOverrides = {
  accent: "accent-text",
  danger: "danger-text",
  success: "success-text",
  warning: "warning-text",
  info: "info-text",
};

// ---------------------------------------------------------------- CSS

function cssTheme() {
  const lines = [];
  const { sans, mono } = tokens.font;
  lines.push(`--font-sans: "${sans.web}", ${sans.fallback};`);
  lines.push(`--font-mono: "${mono.web}", ${mono.fallback};`);
  lines.push("");
  for (const [k, v] of Object.entries(tokens.brand)) lines.push(`--color-brand-${k}: ${v};`);
  lines.push("");
  for (const [k, v] of Object.entries(tokens.tag)) lines.push(`--color-tag-${k}: ${v};`);
  lines.push("");
  for (const name of colorNames) lines.push(`--color-${name}: var(--pb-${name});`);
  for (const [alias, target] of Object.entries(colorAliases)) lines.push(`--color-${alias}: var(--pb-${target});`);
  lines.push("");
  lines.push("/* `text-accent`, `text-danger`, …: the text-safe variant; `bg-*` keeps the fill. */");
  for (const [name, target] of Object.entries(textColorOverrides))
    lines.push(`--text-color-${name}: var(--pb-${target});`);
  lines.push("");
  lines.push("--text-2xs: 0.75rem;");
  lines.push("--text-2xs--line-height: 1rem;");
  for (const [name, t] of Object.entries(tokens.type)) {
    lines.push(`--text-${name}: ${rem(t.size)};`);
    lines.push(`--text-${name}--line-height: ${num(t.line)};`);
    lines.push(`--text-${name}--letter-spacing: ${num(t.tracking)}em;`);
    lines.push(`--text-${name}--font-weight: ${t.weight};`);
  }
  lines.push("");
  for (const [name, r] of Object.entries(tokens.radius)) {
    if (name === "pill" || r.tailwind) continue; // rounded-full and Tailwind's own steps
    lines.push(`--radius-${name}: ${rem(r.value)};`);
  }
  lines.push("");
  for (const [name, p] of Object.entries(tokens.motion.easing)) lines.push(`--ease-${name}: ${bezier(p)};`);
  return lines;
}

function cssVarBlock(theme) {
  const lines = [];
  for (const name of colorNames) lines.push(`--pb-${name}: ${tokens.color[name][theme]};`);
  for (const [name, value] of Object.entries(tokens.shadow[theme])) lines.push(`--pb-shadow-${name}: ${value};`);
  for (const [name, value] of Object.entries(tokens.monogram[theme])) lines.push(`--pb-monogram-${name}: ${value};`);
  return lines;
}

function cssVars() {
  const indent = (lines, n) => lines.map((l) => (l ? " ".repeat(n) + l : l));
  const shared = [];
  for (const [name, ms] of Object.entries(tokens.motion.duration)) shared.push(`--pb-duration-${name}: ${ms}ms;`);
  for (const [name, p] of Object.entries(tokens.motion.easing)) shared.push(`--pb-ease-${name}: ${bezier(p)};`);
  for (const [name, z] of Object.entries(tokens.z)) shared.push(`--pb-z-${name}: ${z};`);
  for (const [name, r] of Object.entries(tokens.radius)) shared.push(`--pb-radius-${name}: ${r.value}px;`);
  for (const [name, g] of Object.entries(tokens.gradient)) {
    const stops = g.stops.map(([at, c]) => `${c} ${Math.round(at * 100)}%`).join(", ");
    shared.push(`--pb-gradient-${name}: linear-gradient(${g.angle}deg, ${stops});`);
  }
  // data-theme also works on any element, for example a light website panel
  // on a dark page: its subtree gets that theme's variables.
  return [
    ":root {",
    ...indent(shared, 2),
    "}",
    "",
    ":root,",
    '[data-theme="light"] {',
    "  color-scheme: light;",
    ...indent(cssVarBlock("light"), 2),
    "}",
    "",
    "@media (prefers-color-scheme: dark) {",
    '  :root:not([data-theme="light"]) {',
    "    color-scheme: dark;",
    ...indent(cssVarBlock("dark"), 4),
    "  }",
    "}",
    "",
    ':root[data-theme="dark"],',
    '[data-theme="dark"] {',
    "  color-scheme: dark;",
    ...indent(cssVarBlock("dark"), 2),
    "}",
  ];
}

function replaceRegion(text, marker, lines, file, indent = "") {
  const start = `/* @generated ${marker}:start — ${GENERATED} */`;
  const end = `/* @generated ${marker}:end */`;
  const i = text.indexOf(start);
  const j = text.indexOf(end);
  if (i < 0 || j < i) throw new Error(`${file}: markers for "${marker}" not found`);
  const body = lines.map((l) => (l ? indent + l : l)).join("\n");
  return `${text.slice(0, i + start.length)}\n${body}\n${indent}${text.slice(j)}`;
}

// ---------------------------------------------------------------- Swift

function swiftFile() {
  const out = [];
  const sans = tokens.font.sans.native;
  const weightName = { 400: "regular", 500: "medium", 600: "semibold", 700: "bold", 800: "heavy" };
  const rgbArgs = (value, name) => {
    const { rgb, alpha } = toSrgb(value, name);
    return `${rgb.map((c) => `0x${hex2(c)}`).join(", ")}, ${num(alpha)}`;
  };
  out.push(`// ${GENERATED}`);
  out.push("//");
  out.push("// Passbox design tokens for SwiftUI (see docs/design/system.md). Colors adapt");
  out.push("// to light and dark mode without asset catalog entries. The fonts in");
  out.push("// Shared/Fonts are registered through UIAppFonts (project.yml).");
  out.push("");
  out.push("import SwiftUI");
  out.push("import UIKit");
  out.push("");
  out.push("enum DesignTokens {");
  out.push("    // MARK: Colors");
  out.push("");
  out.push("    enum Colors {");
  for (const name of colorNames) {
    const c = tokens.color[name];
    out.push(`        /// ${c.use}`);
    out.push(
      `        static let ${camel(name)} = dynamic(light: (${rgbArgs(c.light, name)}), dark: (${rgbArgs(c.dark, name)}))`,
    );
  }
  out.push("");
  out.push("        /// Brand scale (theme independent).");
  for (const [k, v] of Object.entries(tokens.brand))
    out.push(`        static let brand${k} = fixed(${rgbArgs(v, `brand-${k}`)})`);
  out.push("");
  out.push("        /// Category dots and tags (theme independent).");
  for (const [k, v] of Object.entries(tokens.tag))
    out.push(`        static let tag${pascal(k)} = fixed(${rgbArgs(v, `tag-${k}`)})`);
  out.push("");
  out.push("        typealias RGBA = (UInt8, UInt8, UInt8, CGFloat)");
  out.push("");
  out.push("        private static func uiColor(_ c: RGBA) -> UIColor {");
  out.push(
    "            UIColor(red: CGFloat(c.0) / 255, green: CGFloat(c.1) / 255, blue: CGFloat(c.2) / 255, alpha: c.3)",
  );
  out.push("        }");
  out.push("");
  out.push("        private static func dynamic(light: RGBA, dark: RGBA) -> Color {");
  out.push(
    "            Color(uiColor: UIColor { traits in traits.userInterfaceStyle == .dark ? uiColor(dark) : uiColor(light) })",
  );
  out.push("        }");
  out.push("");
  out.push("        static func fixed(_ r: UInt8, _ g: UInt8, _ b: UInt8, _ a: CGFloat) -> Color {");
  out.push("            Color(uiColor: uiColor((r, g, b, a)))");
  out.push("        }");
  out.push("    }");
  out.push("");
  out.push("    // MARK: Typography");
  out.push("");
  out.push(`    /// ${tokens.font.sans.family} (${tokens.font.sans.license}), bundled as static weights.`);
  out.push("    enum FontName {");
  for (const [w, f] of Object.entries(sans)) out.push(`        static let ${weightName[w]} = "${f.postscript}"`);
  out.push("");
  out.push("        static func forWeight(_ weight: Int) -> String {");
  out.push("            switch weight {");
  out.push("            case ..<450: regular");
  out.push("            case ..<550: medium");
  out.push("            case ..<650: semibold");
  out.push("            case ..<750: bold");
  out.push("            default: heavy");
  out.push("            }");
  out.push("        }");
  out.push("    }");
  out.push("");
  const relative = [...new Set(Object.values(tokens.type).map((t) => t.ios))];
  out.push("    /// The Dynamic Type style a step scales with.");
  out.push("    enum RelativeStyle: Sendable {");
  out.push(`        case ${relative.join(", ")}`);
  out.push("");
  out.push("        var fontTextStyle: Font.TextStyle {");
  out.push("            switch self {");
  for (const r of relative) out.push(`            case .${r}: .${r}`);
  out.push("            }");
  out.push("        }");
  out.push("    }");
  out.push("");
  out.push("    /// A step of the type scale. Sizes scale with Dynamic Type relative to `relativeTo`.");
  out.push("    struct TextStyle: Sendable {");
  out.push("        let size: CGFloat");
  out.push("        let weight: Int");
  out.push("        /// Letter spacing in points (tracking × size).");
  out.push("        let tracking: CGFloat");
  out.push("        /// Extra space between lines in points.");
  out.push("        let lineSpacing: CGFloat");
  out.push("        let relativeTo: RelativeStyle");
  out.push("        let uppercase: Bool");
  out.push("        let tabular: Bool");
  out.push("        let mono: Bool");
  out.push("");
  out.push("        var font: Font {");
  out.push("            if mono {");
  out.push(
    "                return Font.system(relativeTo.fontTextStyle, design: .monospaced).weight(DesignTokens.weight(weight))",
  );
  out.push("            }");
  out.push(
    "            return Font.custom(FontName.forWeight(weight), size: size, relativeTo: relativeTo.fontTextStyle)",
  );
  out.push("        }");
  out.push("    }");
  out.push("");
  out.push("    enum Typography {");
  for (const [name, t] of Object.entries(tokens.type)) {
    // SwiftUI's default line height is about 1.2 × size; lineSpacing adds the rest.
    const lineSpacing = Math.max(0, t.size * t.line - t.size * 1.2);
    out.push(`        /// ${t.size} pt, ${t.use}`);
    out.push(
      `        static let ${camel(name)} = TextStyle(size: ${t.size}, weight: ${t.weight}, tracking: ${num(t.tracking * t.size)}, lineSpacing: ${num(lineSpacing)}, relativeTo: .${t.ios}, uppercase: ${!!t.uppercase}, tabular: ${!!t.tabular}, mono: ${!!t.mono})`,
    );
  }
  out.push("    }");
  out.push("");
  out.push("    static func weight(_ value: Int) -> Font.Weight {");
  out.push("        switch value {");
  out.push("        case ..<450: .regular");
  out.push("        case ..<550: .medium");
  out.push("        case ..<650: .semibold");
  out.push("        case ..<750: .bold");
  out.push("        default: .heavy");
  out.push("        }");
  out.push("    }");
  out.push("");
  out.push("    // MARK: Gradients");
  out.push("");
  out.push("    /// Signature gradients (docs/design/brand.md).");
  out.push("    enum Gradients {");
  for (const [name, g] of Object.entries(tokens.gradient)) {
    const stops = g.stops
      .map(([at, c]) => `.init(color: Colors.fixed(${rgbArgs(c, name)}), location: ${at})`)
      .join(", ");
    const points =
      g.angle === 180 ? "startPoint: .top, endPoint: .bottom" : "startPoint: .topLeading, endPoint: .bottomTrailing";
    out.push(`        /// ${g.use}`);
    out.push(`        static var ${camel(name)}: LinearGradient {`);
    out.push(`            LinearGradient(stops: [${stops}], ${points})`);
    out.push("        }");
  }
  out.push("    }");
  out.push("");
  out.push("    // MARK: Shape, space, motion");
  out.push("");
  out.push("    /// Corner radii in points; use with `RoundedRectangle(cornerRadius:style: .continuous)`.");
  out.push("    enum Radius {");
  for (const [name, r] of Object.entries(tokens.radius)) {
    out.push(`        /// ${r.use}`);
    out.push(`        static let ${camel(name)}: CGFloat = ${r.value}`);
  }
  out.push("    }");
  out.push("");
  out.push("    /// 4-point grid.");
  out.push("    enum Space {");
  for (const [name, v] of Object.entries(tokens.space))
    out.push(`        static let s${name.replace(".", "_")}: CGFloat = ${v}`);
  out.push("    }");
  out.push("");
  out.push("    enum Motion {");
  for (const [name, ms] of Object.entries(tokens.motion.duration))
    out.push(`        static let ${name}: Double = ${num(ms / 1000)}`);
  out.push("");
  for (const [name, p] of Object.entries(tokens.motion.easing))
    out.push(
      `        static var ${name}Curve: UnitCurve { .bezier(startControlPoint: UnitPoint(x: ${p[0]}, y: ${p[1]}), endControlPoint: UnitPoint(x: ${p[2]}, y: ${p[3]})) }`,
    );
  out.push("");
  out.push("        /// The standard animation, or none when Reduce Motion is on.");
  out.push("        static func standard(_ duration: Double = base, reduceMotion: Bool) -> Animation? {");
  out.push("            reduceMotion ? nil : .timingCurve(standardCurve, duration: duration)");
  out.push("        }");
  out.push("    }");
  out.push("}");
  out.push("");
  out.push("extension View {");
  out.push("    /// Applies a step of the Passbox type scale (font, tracking, line spacing, case, digits).");
  out.push("    func textStyle(_ style: DesignTokens.TextStyle) -> some View {");
  out.push("        font(style.tabular ? style.font.monospacedDigit() : style.font)");
  out.push("            .tracking(style.tracking)");
  out.push("            .lineSpacing(style.lineSpacing)");
  out.push("            .textCase(style.uppercase ? .uppercase : nil)");
  out.push("    }");
  out.push("}");
  out.push("");
  return out.join("\n");
}

// ---------------------------------------------------------------- Kotlin

function kotlinFile() {
  const out = [];
  const color = (value, name) => `Color(${argb(value, name)})`;
  const k = (theme) => (name) => color(tokens.color[name][theme], `${name} (${theme})`);
  const scheme = (theme) => {
    const c = k(theme);
    const dark = theme === "dark";
    const roles = {
      primary: c("accent"),
      onPrimary: c("accent-contrast"),
      primaryContainer: c("accent-soft"),
      onPrimaryContainer: c("accent-text"),
      inversePrimary: dark ? color(tokens.brand["600"], "brand") : color(tokens.brand["300"], "brand"),
      secondary: c("text-muted"),
      onSecondary: c("canvas"),
      secondaryContainer: c("surface-raised"),
      onSecondaryContainer: c("text"),
      tertiary: c("info"),
      onTertiary: c("canvas"),
      tertiaryContainer: c("info-soft"),
      onTertiaryContainer: c("info-text"),
      background: c("canvas"),
      onBackground: c("text"),
      surface: c("canvas"),
      onSurface: c("text"),
      surfaceVariant: c("surface-raised"),
      onSurfaceVariant: c("text-muted"),
      surfaceTint: "Color.Transparent",
      inverseSurface: c("surface-inverse"),
      inverseOnSurface: c("text-inverse"),
      error: c("danger"),
      onError: c("danger-contrast"),
      errorContainer: c("danger-soft"),
      onErrorContainer: c("danger-text"),
      outline: c("border-strong"),
      outlineVariant: c("border"),
      scrim: "Color.Black",
      surfaceBright: dark ? c("surface-overlay") : c("surface"),
      surfaceDim: dark ? c("surface-sunken") : c("surface-sunken"),
      surfaceContainerLowest: dark ? c("surface-sunken") : c("surface"),
      surfaceContainerLow: c("surface"),
      surfaceContainer: c("surface"),
      surfaceContainerHigh: c("surface-raised"),
      surfaceContainerHighest: dark ? c("surface-overlay") : c("surface-sunken"),
    };
    return Object.entries(roles).map(([role, v]) => `    ${role} = ${v},`);
  };

  out.push(`// ${GENERATED}`);
  out.push("//");
  out.push("// Passbox design tokens for Jetpack Compose (see docs/design/system.md):");
  out.push("// Material color schemes, the full semantic palette, type scale with the");
  out.push("// bundled Plus Jakarta Sans (res/font), shapes, spacing and motion.");
  out.push("");
  out.push("package dev.passbox.android.ui.theme");
  out.push("");
  out.push("import androidx.compose.animation.core.CubicBezierEasing");
  out.push("import androidx.compose.foundation.shape.RoundedCornerShape");
  out.push("import androidx.compose.material3.ColorScheme");
  out.push("import androidx.compose.material3.Shapes");
  out.push("import androidx.compose.material3.Typography");
  out.push("import androidx.compose.material3.darkColorScheme");
  out.push("import androidx.compose.material3.lightColorScheme");
  out.push("import androidx.compose.runtime.Immutable");
  out.push("import androidx.compose.runtime.staticCompositionLocalOf");
  out.push("import androidx.compose.ui.graphics.Brush");
  out.push("import androidx.compose.ui.graphics.Color");
  out.push("import androidx.compose.ui.text.TextStyle");
  out.push("import androidx.compose.ui.text.font.Font");
  out.push("import androidx.compose.ui.text.font.FontFamily");
  out.push("import androidx.compose.ui.text.font.FontWeight");
  out.push("import androidx.compose.ui.unit.dp");
  out.push("import androidx.compose.ui.unit.em");
  out.push("import androidx.compose.ui.unit.sp");
  out.push("import dev.passbox.android.R");
  out.push("");
  out.push(`/** ${tokens.font.sans.family} (${tokens.font.sans.license}), static weights in res/font. */`);
  out.push("val PassboxSans = FontFamily(");
  for (const [w, f] of Object.entries(tokens.font.sans.native))
    out.push(`    Font(R.font.${f.android}, FontWeight(${w})),`);
  out.push(")");
  out.push("");
  out.push("/** Every semantic color of the Passbox palette, for what Material's scheme does not cover. */");
  out.push("@Immutable");
  out.push("data class PassboxColors(");
  for (const name of colorNames) out.push(`    val ${camel(name)}: Color,`);
  out.push(")");
  out.push("");
  for (const theme of themes) {
    out.push(`val ${theme === "light" ? "Light" : "Dark"}PassboxColors = PassboxColors(`);
    for (const name of colorNames) out.push(`    ${camel(name)} = ${k(theme)(name)},`);
    out.push(")");
    out.push("");
  }
  out.push("val LocalPassboxColors = staticCompositionLocalOf { LightPassboxColors }");
  out.push("");
  out.push("/** Brand scale and category dot colors (theme independent). */");
  out.push("object PassboxPalette {");
  for (const [n, v] of Object.entries(tokens.brand)) out.push(`    val Brand${n} = ${color(v, `brand-${n}`)}`);
  for (const [n, v] of Object.entries(tokens.tag)) out.push(`    val Tag${pascal(n)} = ${color(v, `tag-${n}`)}`);
  out.push("}");
  out.push("");
  for (const theme of themes) {
    const fn = theme === "light" ? "lightColorScheme" : "darkColorScheme";
    out.push(`val Passbox${theme === "light" ? "Light" : "Dark"}ColorScheme: ColorScheme = ${fn}(`);
    out.push(...scheme(theme));
    out.push(")");
    out.push("");
  }
  out.push("/** Every step of the type scale (docs/design/system.md). */");
  out.push("object PassboxType {");
  for (const [name, t] of Object.entries(tokens.type)) {
    const family = t.mono ? "FontFamily.Monospace" : "PassboxSans";
    const features = t.tabular || t.mono ? `, fontFeatureSettings = "tnum"` : "";
    out.push(`    /** ${t.size} sp, ${t.use}${t.uppercase ? " (set in uppercase)" : ""}. */`);
    out.push(
      `    val ${pascal(name)} = TextStyle(fontFamily = ${family}, fontWeight = FontWeight(${t.weight}), fontSize = ${t.size}.sp, lineHeight = ${num(t.size * t.line)}.sp, letterSpacing = ${num(t.tracking)}.em${features})`,
    );
  }
  out.push("}");
  out.push("");
  const material = {
    displayLarge: "Display",
    displayMedium: "DisplaySm",
    displaySmall: "TitleLg",
    headlineLarge: "TitleLg",
    headlineMedium: "Title",
    headlineSmall: "TitleSm",
    titleLarge: "TitleSm",
    titleMedium: "Headline",
    titleSmall: "Label",
    bodyLarge: "BodyLg",
    bodyMedium: "Body",
    bodySmall: "Caption",
    labelLarge: "Label",
    labelMedium: "LabelSm",
    labelSmall: "Overline",
  };
  out.push("/** Material 3 roles mapped onto the Passbox type scale. */");
  out.push("val PassboxTypography = Typography(");
  for (const [role, step] of Object.entries(material)) out.push(`    ${role} = PassboxType.${step},`);
  out.push(")");
  out.push("");
  out.push("/** Corner radii in dp. */");
  out.push("object PassboxRadius {");
  for (const [name, r] of Object.entries(tokens.radius))
    out.push(`    /** ${r.use} */\n    val ${pascal(name)} = ${r.value}.dp`);
  out.push("}");
  out.push("");
  out.push("val PassboxShapeScale = Shapes(");
  out.push(`    extraSmall = RoundedCornerShape(PassboxRadius.Sm),`);
  out.push(`    small = RoundedCornerShape(PassboxRadius.Control),`);
  out.push(`    medium = RoundedCornerShape(PassboxRadius.Card),`);
  out.push(`    large = RoundedCornerShape(PassboxRadius.Panel),`);
  out.push(`    extraLarge = RoundedCornerShape(PassboxRadius.Sheet),`);
  out.push(")");
  out.push("");
  out.push("/** Signature gradients (docs/design/brand.md). */");
  out.push("object PassboxGradients {");
  for (const [name, g] of Object.entries(tokens.gradient)) {
    const stops = g.stops.map(([at, c]) => `${at}f to ${color(c, name)}`).join(", ");
    const brush = g.angle === 180 ? "verticalGradient" : "linearGradient";
    out.push(`    /** ${g.use} */`);
    out.push(`    val ${pascal(name)}: Brush get() = Brush.${brush}(${stops})`);
  }
  out.push("}");
  out.push("");
  out.push("/** 4 dp grid. */");
  out.push("object PassboxSpace {");
  for (const [name, v] of Object.entries(tokens.space)) out.push(`    val S${name.replace(".", "_")} = ${v}.dp`);
  out.push("}");
  out.push("");
  out.push("/** Durations in milliseconds and easing curves; skip non-essential motion when animations are off. */");
  out.push("object PassboxMotionTokens {");
  for (const [name, ms] of Object.entries(tokens.motion.duration)) out.push(`    const val ${pascal(name)} = ${ms}`);
  for (const [name, p] of Object.entries(tokens.motion.easing))
    out.push(`    val ${pascal(name)}Easing = CubicBezierEasing(${p.map((x) => `${x}f`).join(", ")})`);
  out.push("}");
  out.push("");
  return out.join("\n");
}

// ---------------------------------------------------------------- docs

function docsTables() {
  const lines = [];
  lines.push("| Token | Light | Dark | Use |");
  lines.push("| --- | --- | --- | --- |");
  for (const name of colorNames) {
    const c = tokens.color[name];
    const fmt = (theme) =>
      `\`${c[theme].replace(/^oklch\(|\)$/g, "")}\` ${hexRgb(c[theme], name)}${parseOklch(c[theme]).alpha < 1 ? ` @ ${Math.round(parseOklch(c[theme]).alpha * 100)} %` : ""}`;
    lines.push(`| \`${name}\` | ${fmt("light")} | ${fmt("dark")} | ${c.use} |`);
  }
  lines.push("");
  lines.push(
    "Aliases: " +
      Object.entries(colorAliases)
        .map(([a, t]) => `\`${a}\` → \`${t}\``)
        .join(", ") +
      ".",
  );
  lines.push("");
  lines.push(
    "Brand scale (theme independent): " +
      Object.entries(tokens.brand)
        .map(([k, v]) => `\`${k}\` ${hexRgb(v, k)}`)
        .join(", ") +
      ".",
  );
  lines.push("");
  lines.push(
    "Category dots (`tag-*`, theme independent): " +
      Object.entries(tokens.tag)
        .map(([k, v]) => `\`${k}\` ${hexRgb(v, k)}`)
        .join(", ") +
      ".",
  );
  lines.push("");
  lines.push("### Checked contrast pairs");
  lines.push("");
  lines.push("| Foreground | Background | Target | Light | Dark |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const [fg, bg, target] of tokens.contrast) {
    const r = (theme) => contrastResults.find((x) => x.fg === fg && x.bg === bg && x.theme === theme).ratio.toFixed(2);
    lines.push(`| \`${fg}\` | \`${bg}\` | ${target}:1 | ${r("light")} | ${r("dark")} |`);
  }
  lines.push("");
  lines.push("### Type scale");
  lines.push("");
  lines.push("| Step | Size (px/pt/sp) | Line height | Tracking | Weight | iOS Dynamic Type | Use |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- |");
  for (const [name, t] of Object.entries(tokens.type)) {
    const extra = [t.uppercase && "uppercase", t.tabular && "tabular nums", t.mono && "mono"]
      .filter(Boolean)
      .join(", ");
    lines.push(
      `| \`${name}\` | ${t.size} | ${t.line} | ${t.tracking} em | ${t.weight}${extra ? ` (${extra})` : ""} | \`.${t.ios}\` | ${t.use} |`,
    );
  }
  lines.push("");
  lines.push("### Gradients");
  lines.push("");
  for (const [name, g] of Object.entries(tokens.gradient)) {
    const stops = g.stops.map(([at, c]) => `${hexRgb(c, name)} ${Math.round(at * 100)} %`).join(" → ");
    lines.push(`- \`${name}\` (${g.angle}°): ${stops}. ${g.use}`);
  }
  lines.push("");
  lines.push("### Radii");
  lines.push("");
  lines.push("| Token | Value | Use |");
  lines.push("| --- | --- | --- |");
  for (const [name, r] of Object.entries(tokens.radius))
    lines.push(`| \`${name}\` | ${name === "pill" ? "full" : `${r.value} px`} | ${r.use} |`);
  lines.push("");
  lines.push("### Spacing, motion, layers");
  lines.push("");
  lines.push(
    "- Spacing (4 px grid): " +
      Object.entries(tokens.space)
        .map(([k, v]) => `\`${k}\` ${v}`)
        .join(", ") +
      ".",
  );
  lines.push(
    "- Durations: " +
      Object.entries(tokens.motion.duration)
        .map(([k, v]) => `\`${k}\` ${v} ms`)
        .join(", ") +
      ".",
  );
  lines.push(
    "- Easing: " +
      Object.entries(tokens.motion.easing)
        .map(([k, v]) => `\`${k}\` ${bezier(v)}`)
        .join(", ") +
      ".",
  );
  lines.push(
    "- Layers (`--pb-z-*`): " +
      Object.entries(tokens.z)
        .map(([k, v]) => `\`${k}\` ${v}`)
        .join(", ") +
      ".",
  );
  return lines;
}

function replaceMdRegion(text, marker, lines, file) {
  const start = `<!-- @generated ${marker}:start — ${GENERATED} -->`;
  const end = `<!-- @generated ${marker}:end -->`;
  const i = text.indexOf(start);
  const j = text.indexOf(end);
  if (i < 0 || j < i) throw new Error(`${file}: markers for "${marker}" not found`);
  return `${text.slice(0, i + start.length)}\n${lines.join("\n")}\n${text.slice(j)}`;
}

// ---------------------------------------------------------------- write

/** Formats CSS and HTML like `pnpm lint` expects (Biome), so the check compares like with like. */
function biomeFormat(path, text) {
  if (!path.endsWith(".css")) return text;
  const biome = join(root, "node_modules/.bin/biome");
  if (!existsSync(biome)) return text;
  return execFileSync(biome, ["format", `--stdin-file-path=${path}`], { input: text, cwd: root, encoding: "utf8" });
}

const outputs = [];
function output(path, produce) {
  const file = join(root, path);
  let current = "";
  try {
    current = readFileSync(file, "utf8");
  } catch {
    current = "";
  }
  outputs.push({ path, file, current, next: biomeFormat(path, produce(current)) });
}

output("packages/ui/src/tokens.css", (text) =>
  replaceRegion(replaceRegion(text, "theme", cssTheme(), "tokens.css", "  "), "vars", cssVars(), "tokens.css", "  "),
);
output("docs/design/board.html", (text) => replaceRegion(text, "vars", cssVars(), "board.html", "      "));
output("apps/ios/Shared/DesignTokens.swift", () => swiftFile());
output("apps/android/app/src/main/java/dev/passbox/android/ui/theme/Tokens.kt", () => kotlinFile());
output("docs/design/system.md", (text) => replaceMdRegion(text, "tokens", docsTables(), "system.md"));

let changed = 0;
for (const { path, file, current, next } of outputs) {
  if (current === next) continue;
  if (check) {
    changed++;
    problems.add(`${path} is out of date; run node scripts/generate-design-tokens.mjs`);
  } else {
    changed++;
    writeFileSync(file, next);
    console.log(`wrote ${relative(root, file)}`);
  }
}
if (problems.size) {
  for (const p of problems) console.error(`error: ${p}`);
  process.exit(1);
}
if (check)
  console.log(`design tokens: ${outputs.length} files current, ${contrastResults.length} contrast checks pass`);
else if (!changed) console.log("design tokens up to date");
