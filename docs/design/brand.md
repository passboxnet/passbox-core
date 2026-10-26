# Passbox brand line

Passbox must be recognisable at a glance on every surface: website, web app,
desktop app, browser extension, iOS, Android and the server's pages and
emails. Six signature elements carry the brand. They are generated from one
set of sources, so they cannot drift apart. The colours are **Passbox
Marina**: Nocturnal Marina, Solar Silk and Sky Horizon (section 2).

```
node scripts/generate-design-tokens.mjs   # colors, type, gradients (docs/design/system.md)
node scripts/generate-brand-assets.mjs    # logo, app icons, icon family, board assets
```

`generate-brand-assets.mjs` renders with Playwright's Chromium (installed for
the e2e tests). Commit everything it writes. See [board.html](board.html) for
the brand sheet.

## 1. Logo and app icons

**The mark** is a Solar Silk keyhole (a circle over a tapered stem with
rounded feet) on a rounded Nocturnal Marina tile filled with the signature
gradient, with a soft Sky glow in the top-left corner and a thin inner edge.
The wordmark is “Passbox” in Plus Jakarta Sans Bold, −0.02 em tracking, set to
the right of the mark with a gap of 30–40 % of the mark size, in Marina ink
(`text`, #11262F) on light backgrounds and near-white on dark ones.

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
  Solar glyph alone; on Solar, the glyph in Marina.

| Platform | Asset | Wired in |
| --- | --- | --- |
| iOS / iPadOS | `AppIcon.appiconset`: light (Marina gradient, Solar glyph, opaque), dark (Solar glyph on transparent; the system draws the dark background), tinted (grayscale on black), 1024 px each | `apps/ios/Passbox/Assets.xcassets`, `ASSETCATALOG_COMPILER_APPICON_NAME` |
| Android | Adaptive icon: Marina gradient background vector with the Sky glow, Solar glyph foreground (inside the 66 dp safe zone), monochrome layer for themed icons; Play Store PNG 512 px | `res/mipmap-anydpi-v26/ic_launcher.xml`, `res/drawable/ic_launcher_*.xml`, `src/main/ic_launcher-playstore.png` |
| Desktop (Tauri) | macOS-grid icon (824 px tile on 1024 px with shadow) as PNGs, `icon.icns`, `icon.ico`, Windows Store tiles | `apps/desktop/src-tauri/icons`, `tauri.conf.json` |
| Browser extension | 16, 32, 48, 128 px (128 with 16 px padding) | `apps/extension/public/icons`, `manifest.json` |
| Web app, website | `favicon.svg`, `favicon.ico` (16 + 32), `apple-touch-icon.png` (180, opaque), `icon-512.png` | `apps/web/index.html`, `apps/website/components/SiteDocument.tsx` |
| Emails | `packages/ui/brand/png/email-logo@2x.png` (mark + wordmark, 164 × 48 at 2×, for light backgrounds) and `email-logo-dark@2x.png` | Attached to every mail as inline images (`cid:logo-light@passbox`, `cid:logo-dark@passbox`; `crates/server/src/mail/layout.rs`), so no remote image is loaded; also served at `/assets/mail/logo-light.png` and `/assets/mail/logo-dark.png`. The alt text “Passbox” is styled as the wordmark, so the header still reads with images off. |

## 2. Colours and the signature gradient

Three brand colours (`palette` in `tokens.json`; CSS `--color-marina` …,
SwiftUI `DesignTokens.Colors.marina` …, Compose `PassboxPalette.Marina` …,
Rust `brand::tokens::palette::MARINA` …):

| Colour | Hex | Lip | Role |
| --- | --- | --- | --- |
| **Nocturnal Marina** | `#243E4B` | `#0B1A21` | Brand base: logo tile, app icon background, dark surfaces (the dark `surface-overlay` is Marina itself), ink on Solar. |
| **Solar Silk** | `#FFE26D` | `#F5C443` | The signature accent, used sparingly so it pops: primary pill buttons, the raised “+”, the logo glyph, the dark-theme focus ring and links. |
| **Sky Horizon** | `#6EABC7` | `#44739A` | Secondary: selection tints, info, secondary highlights, charts, illustrations. Never the primary action. |

Rules that keep it legible:

- **Solar always carries Marina ink**, never white (`accent-contrast`,
  12:1). Solar is a fill, never a text colour on light backgrounds.
- **Light theme:** primary buttons stay Solar with Marina ink and get the
  ochre lip (`accent-edge`, 3.4:1 against white) so they read on white.
  Links and accent text are deep Sky (`accent-text` #1E5F7D), focus rings,
  switches and checkboxes Marina.
- **Dark theme:** canvas and surfaces are a deep Marina family; links,
  focus rings, switches and checkboxes are Solar.
- **Selection** (selected list row, active navigation item, selected tab) is
  a Sky tint (`selection`) with a marker in `selection-marker` (Marina in
  light, Solar in dark) — never a full Solar fill, which is reserved for the
  primary action and the “+”.
- **Status colours stay apart from Solar:** warning is a clear orange
  (hue 50, not yellow), danger red, success green, info Sky. The orange
  update banner and the Mehrfach/Schwach stat tiles must never look like
  the brand yellow.

**The signature gradient** is Marina: lighter Marina → Nocturnal Marina →
deep Marina at 135° (`gradient.signature`: `#36596A → #243E4B → #12232B`).
It fills the mark, the app icons and brand panels (the dark half of the
sign-in screens, the Emergency Kit band, the email band). Its companion is the
**backdrop** gradient (deep Marina, lighter towards the top) with a soft Sky
glow from the top, a very soft Solar glow in the lower right and fine grain,
behind website panels and onboarding.

- CSS: `var(--pb-gradient-signature)`, `bg-signature`; backdrop
  `bg-backdrop` + `grain`; glows `--color-glow-sky`, `--color-glow-solar`.
- SwiftUI: `DesignTokens.Gradients.signature`, `.backdrop`;
  `DesignTokens.Colors.glowSky`, `.glowSolar`.
- Compose: `PassboxGradients.Signature`, `.Backdrop`;
  `PassboxPalette.GlowSky`, `.GlowSolar`.
- Never behind body text, never on every card, never as a text fill for long
  copy.

**Why these colours.** Every big password manager owns a colour: 1Password
and Bitwarden blue, LastPass and Passbolt red, Proton Pass violet, Dashlane
green/teal, NordPass teal. Keeper also uses a yellow, but a saturated
`#FFC700` on black; Passbox pairs a soft Solar yellow with teal-navy Marina
and muted Sky, so neither the yellow nor the navy alone carries the brand —
the combination does. The previous electric blue (`#276CF3`) is retired
everywhere.

### The lip

The reference palette shows stacked rounded cards, each with a darker lip
along the bottom edge. Passbox uses that lip as a quiet 3D motif:

- **Primary pill buttons and the raised “+”**: a 2 px bottom edge in
  `accent-edge` (`shadow-lip`; with glow on hover `shadow-lip-glow`). Pressed
  removes the lip (the button sits down).
- **Stat tiles and category cards**: a 3 px darker bottom edge
  (`shadow-stack` with the `card-edge` colour).
- The lip is a static edge, never animated, so reduced motion changes
  nothing. It is not used on text fields, list rows or dialogs.

## 3. Panel and dotted-grid motif

Content on the website and in onboarding sits in large rounded **panels**
(24 px inner radius) with a soft translucent **bezel** (10 px) on the
backdrop. Panels alternate light and near-black (`Panel theme="light|dark"`).
Inside, **dotted hairlines** mark the content edges and section breaks, with
small **corner dots** where they cross (`GridFrame`, utilities `dotted-x`,
`dotted-y`). The motif is decoration only: never as a background behind text
in the app, never animated.

The motif also frames the app's **empty states** (`EmptyState`: the Solar icon on
the Marina signature gradient tile with its lip inside dotted rings with corner dots) and the
**Emergency Kit** PDF (`apps/web/src/lib/kit.ts`: a band in the Marina signature
gradient with its lip, the Solar keyhole and the wordmark, dotted guides along the
content with corner dots, rounded tinted boxes for the Secret Key and the
recovery code).

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
- **Selected row in a Sky tint** with a Marina (light) or Solar (dark)
  marker and the normal text colour (desktop, web, extension, iPad).
- **Raised round “+”** in Solar with a Marina “+”, the lip and a soft glow in
  the middle of the mobile bottom bar; a round “+” floating action in
  desktop lists.
- **Solar pill calls to action** (“Kostenlos starten”) with Marina ink and
  the lip, and a secondary outline pill.
- **Big-number stat tiles** for security status, stacked with a lip, with
  the tone in a small icon chip, and the **alert card** above them.
- **Orange inline banner** for “Zeit, Ihr Passwort zu ändern · Jetzt ändern”.
- **Large titles** on mobile, two-line headlines on the website.

## 7. The server's own surfaces

The server renders a few things itself; they carry the same brand line:

- **Emails** (`crates/server/src/mail/layout.rs`): one table-based layout
  with inline styles. Light theme inline (readable in every client), dark
  theme through `prefers-color-scheme` (and Outlook.com's `[data-ogsc]`).
  Logo header, a 6 px band in the signature gradient (solid
  Marina `#243E4B` fallback) with a Solar accent, the panel (24 px radius) with
  dotted guides and four corner dots, details in a rounded well, a Solar pill
  button with Marina text and the link repeated as text below it, and a footer with the template's reason, the
  instance name and its address. Plain-text alternatives are unchanged.
  Previews of every template in both languages:
  `cargo run -p passbox-server --example mail-previews -- <dir>`.
- **Pages** (`crates/server/src/brand`): without a web vault
  (`PASSBOX_WEB_DIR` unset) browsers get a start page with the server
  address, a branded 404, and single sign-on errors (when no
  `PASSBOX_PUBLIC_URL` is set to redirect to). They use the backdrop
  gradient with grain, a bezelled panel with the dotted grid frame, the mark,
  Plus Jakarta Sans served by the instance (`/assets/brand/*.woff2`) and pill
  buttons, in light and dark.
- Colors come from `crates/server/src/brand/tokens.rs`, generated from
  `tokens.json` like every other platform (sRGB, because email clients do not
  understand OKLCH).
