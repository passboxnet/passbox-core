# Passbox brand line

Passbox must be recognisable at a glance on every surface: website, web app,
desktop app, browser extension, iOS, Android and the server's pages and
emails. Six signature elements carry the brand. They are generated from one
set of sources, so they cannot drift apart:

```
node scripts/generate-design-tokens.mjs   # colors, type, gradients (docs/design/system.md)
node scripts/generate-brand-assets.mjs    # logo, app icons, icon family, board assets
```

`generate-brand-assets.mjs` renders with Playwright's Chromium (installed for
the e2e tests). Commit everything it writes. See [board.html](board.html) for
the brand sheet.

## 1. Logo and app icons

**The mark** is a white keyhole (a circle over a tapered stem with rounded
feet) on a rounded tile filled with the signature gradient, with a soft
highlight in the top-left corner and a thin inner edge. The wordmark is
“Passbox” in Plus Jakarta Sans Bold, −0.02 em tracking, set to the right of
the mark with a gap of 30–40 % of the mark size.

- Sources: `packages/ui/brand/mark.svg` (32-unit grid, tile radius 9 = 28 %),
  `mark-small.svg` (no inner edge, for 16–32 px), `glyph.svg` (keyhole only,
  `currentColor`), `app-icon.svg` (full-bleed 1024 px square; platforms round
  it), `app-icon-dark.svg`, `app-icon-tinted.svg`, and the desktop icon in
  `apps/desktop/assets/icon.svg`. The geometry lives in one place
  (`GLYPH` in `scripts/generate-brand-assets.mjs`); the React `Logo` in
  `packages/ui/src/Logo.tsx` uses the same paths.
- Clear space: half the mark's size on every side. Minimum size 16 px.
- Never recolor the tile, outline the mark, rotate or stretch it, put it on a
  busy photo, or add effects. On the signature gradient or a photo, use the
  white glyph alone.

| Platform | Asset | Wired in |
| --- | --- | --- |
| iOS / iPadOS | `AppIcon.appiconset`: light (opaque), dark (glyph on transparent), tinted (grayscale on black), 1024 px each | `apps/ios/Passbox/Assets.xcassets`, `ASSETCATALOG_COMPILER_APPICON_NAME` |
| Android | Adaptive icon: gradient background vector, white glyph foreground (inside the 66 dp safe zone), monochrome layer for themed icons; Play Store PNG 512 px | `res/mipmap-anydpi-v26/ic_launcher.xml`, `res/drawable/ic_launcher_*.xml`, `src/main/ic_launcher-playstore.png` |
| Desktop (Tauri) | macOS-grid icon (824 px tile on 1024 px with shadow) as PNGs, `icon.icns`, `icon.ico`, Windows Store tiles | `apps/desktop/src-tauri/icons`, `tauri.conf.json` |
| Browser extension | 16, 32, 48, 128 px (128 with 16 px padding) | `apps/extension/public/icons`, `manifest.json` |
| Web app, website | `favicon.svg`, `favicon.ico` (16 + 32), `apple-touch-icon.png` (180, opaque), `icon-512.png` | `apps/web/index.html`, `apps/website/components/SiteDocument.tsx` |
| Emails | `packages/ui/brand/png/email-logo@2x.png` (mark + wordmark, 164 × 48 at 2×, for light backgrounds) and `email-logo-dark@2x.png` | To be served by the server and referenced from `crates/server/src/mail/templates.rs` when the emails are restyled; emails must not depend on the image (alt text “Passbox”, the wordmark also as text). |

## 2. The signature gradient

Sky blue → electric blue → deep indigo at 135° (`gradient.signature` in
`tokens.json`: `#5EA8F9 → #2061F5 → #1A2C94`). It fills the mark, the app
icons, the raised “+” button and, sparingly, hero accents. Its companion is
the **backdrop** gradient (deep navy into electric blue, top to bottom, with a
glow from below and fine grain) behind website panels and onboarding.

- CSS: `var(--pb-gradient-signature)`, `bg-signature`; backdrop
  `bg-backdrop` + `grain`.
- SwiftUI: `DesignTokens.Gradients.signature`, `.backdrop`.
- Compose: `PassboxGradients.Signature`, `.Backdrop`.
- Never behind body text, never on every card, never as a text fill for long
  copy.

## 3. Panel and dotted-grid motif

Content on the website and in onboarding sits in large rounded **panels**
(24 px inner radius) with a soft translucent **bezel** (10 px) on the
backdrop. Panels alternate light and near-black (`Panel theme="light|dark"`).
Inside, **dotted hairlines** mark the content edges and section breaks, with
small **corner dots** where they cross (`GridFrame`, utilities `dotted-x`,
`dotted-y`). The motif is decoration only: never as a background behind text
in the app, never animated.

## 4. One icon family

Lucide outline icons on every platform: 24 × 24, 2 px stroke, round caps and
joins (ISC license; icons derived from Feather are MIT, see
THIRD_PARTY_NOTICES.md).

- Web, extension, desktop, website: `lucide-react`.
- iOS: `apps/ios/Shared/Icons.xcassets` (template SVGs that keep their vector
  data) and `PassboxIcon` (`PassboxIcon.keyRound.image`), in both the app and
  the AutoFill extension. Prefer these over SF Symbols for Passbox concepts so
  the apps match the web; system controls (share sheet, navigation back) may
  keep their system glyphs.
- Android: `res/drawable/pb_icon_*.xml` vector drawables and `PassboxIcons`
  (`painterResource(PassboxIcons.KeyRound)`), instead of Material icons for
  Passbox concepts.
- The exported set is `packages/ui/brand/icons.json`; add a Lucide name there
  and rerun the script.

## 5. One typeface

Plus Jakarta Sans everywhere (OFL 1.1), JetBrains Mono for secrets on the web.
Display sizes with tight tracking, two-line headlines on the website. Details
in [system.md](system.md#typography).

## 6. Signature components

These shapes say “Passbox” before the logo does; use them consistently:

- **Icon tiles**: real favicons on light rounded tiles (28 % radius), the same
  in lists, details and autofill.
- **Selected row in solid electric blue** with white text (desktop, web,
  extension, iPad).
- **Raised round “+”** on the signature gradient in the middle of the mobile
  bottom bar; a round “+” floating action in desktop lists.
- **Pill calls to action** (“Kostenlos starten”) with a secondary outline pill.
- **Big-number stat tiles** for security status, with the tone in a small
  icon chip, and the **alert card** above them.
- **Orange inline banner** for “Zeit, Ihr Passwort zu ändern · Jetzt ändern”.
- **Large titles** on mobile, two-line headlines on the website.
