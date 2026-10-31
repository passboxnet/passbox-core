# Passbox design system ("Passbox Marina")

The visual language of every Passbox surface: website, web app, desktop app,
browser extension, iOS, Android and the server's own pages and emails. The
brand elements (logo, app icons, gradient, motif, icon family) are in
[brand.md](brand.md); the visual board is [board.html](board.html) (open it in
a browser).

**Direction:** dark-first, premium and calm. Deep Marina surfaces, one Solar
Silk accent used sparingly, Sky Horizon for selection and information,
generous radii, hairline borders, elevation through lighter surfaces rather
than heavy shadows, the stacked-card lip as a quiet 3D motif, and a light
theme on warm paper designed with the same care (not an inversion). The
system default theme is respected everywhere. Colour roles and the reasoning
behind them: [brand.md](brand.md#2-colours-and-the-signature-gradient).

## Sources and outputs

One source, generated everywhere:

| What | Where |
| --- | --- |
| Token source (colors, type, radii, spacing, motion, layers, gradients) | `packages/ui/tokens/tokens.json` |
| Generator and checks (sRGB gamut, WCAG contrast, stale outputs) | `scripts/generate-design-tokens.mjs` (`pnpm --filter @passbox/ui tokens`; `pnpm test` runs `--check`) |
| Web, extension, desktop, website | `packages/ui/src/tokens.css` (Tailwind CSS v4 `@theme` + CSS variables `--pb-*`) |
| iOS | `Shared/DesignTokens.swift` in passboxnet/ios (dynamic light/dark colors without asset catalog entries, type scale, radii, spacing, motion, gradients) |
| Android | `app/src/main/java/dev/passbox/android/ui/theme/Tokens.kt` in passboxnet/android (Material `ColorScheme` light/dark with `primary` = `control`, so Material text buttons and switches never show Solar on white; `PassboxColors`, `PassboxTokenTypography`, `PassboxShapeScale`, spacing, motion, gradients) |
| Server pages and emails | `src/brand/tokens.rs` in passboxnet/server (sRGB colors per theme, gradients, font stacks, radii) |
| Logo, app icons, icon family | `scripts/generate-brand-assets.mjs`, see [brand.md](brand.md) |

Change a value in `tokens.json`, run `node scripts/generate-design-tokens.mjs`
and commit every changed file. Never edit generated regions by hand.

## Typography

- **Sans:** Plus Jakarta Sans (SIL Open Font License 1.1), a geometric sans with
  tabular figures, `case` forms and full Latin Extended (German, Polish,
  Vietnamese …). Web: `@fontsource-variable/plus-jakarta-sans` (variable
  200–800) via `@passbox/ui/fonts.css`, bundled by Vite and Next.js, no font
  CDN. iOS: static TTFs in `Shared/Fonts` (registered with
  `UIAppFonts` in `project.yml`). Android: `res/font/plus_jakarta_sans_*.ttf`.
  The static weights (400, 500, 600, 700, 800) are instances of the variable
  font made with fontTools:
  `fonttools varLib.instancer "PlusJakartaSans[wght].ttf" wght=600 --update-name-table -o PlusJakartaSans-SemiBold.ttf`.
- **Mono:** JetBrains Mono (OFL 1.1) on the web for passwords, codes and keys;
  the native apps use the platform monospace (SF Mono, Android monospace).
- **Emails:** fonts are not embedded in emails; use the stack
  `"Plus Jakarta Sans", -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif`.
- Display sizes track tight (−0.035 em at 72 px down to −0.01 em at 18 px);
  body text has no tracking. Big numbers (`stat`) use tabular figures.
- Web app body text is 14 px. On iOS every step scales with Dynamic Type
  relative to the listed text style (`Font.custom(_:size:relativeTo:)`); on
  Android sizes are `sp`, so they follow the system font scale.
- Tailwind utilities: `text-display-xl`, `text-display`, `text-display-sm`,
  `text-title-lg`, `text-title`, `text-title-sm`, `text-headline`,
  `text-body-lg`, `text-body`, `text-body-sm`, `text-label`, `text-label-sm`,
  `text-caption`, `text-overline`, `text-stat`, `text-mono` (each sets size,
  line height, tracking and weight). SwiftUI: `.textStyle(DesignTokens.Typography.titleLg)`.
  Compose: `PassboxType.TitleLg` or the Material roles in `PassboxTokenTypography`.

## Color

Semantic tokens only; never hard-code colors. In Tailwind every token is a
color utility (`bg-surface`, `text-text-muted`, `border-hairline`,
`bg-accent`, …). Two rules keep contrast right:

- **Fill vs. text.** `accent`, `success`, `warning`, `danger` and `info` are
  fills and icon colors. Text in those colors uses the `*-text` variant, which
  is tuned for 4.5:1 on the canvas and surfaces. In Tailwind, `text-accent`,
  `text-danger`, `text-success`, `text-warning` and `text-info` already map to
  the text variants (`--text-color-*`), while `bg-*`, `border-*` and `ring-*`
  use the fill. Text on a fill uses `*-contrast`: Marina ink on Solar
  (`accent-contrast`) and on the orange warning fill, white on success (light)
  and danger.
- **Solar is a fill, not a text colour on light.** `accent` is Solar Silk in
  both themes; `accent-text` is deep Sky in light and Solar in dark. Checked
  controls (switch tracks, checkboxes, radios, progress) use `control` /
  `control-contrast` (Marina with white in light, Solar with Marina ink in
  dark), because a Solar track has no contrast on white.
- **Selection is Sky.** Selected rows, the active navigation item and selected
  tabs use `selection` with `selection-marker`; Solar fills are reserved for
  the primary action and the raised “+”.
- **Elevation is lightness.** In dark mode surfaces get lighter as they rise
  (canvas → surface → surface-raised → surface-overlay); shadows are subtle
  and add a 1 px top highlight. In light mode surfaces are white on an
  off-white canvas with soft shadows.

`data-theme="light"` or `data-theme="dark"` works on `<html>` (forced theme)
and on any element (a light website panel on a dark page). This works because
the semantic colors and shadows are declared `@theme inline`: `bg-surface`
compiles to `var(--pb-surface)` and resolves on the element itself
(`app/src/themeTokens.test.ts` in passboxnet/web guards it).

## Shape, space and elevation

- 4 px spacing grid (Tailwind's default spacing scale).
- Radii: controls 12 px, cards 20 px, panels and windows 24 px, sheets 28 px,
  pills and switches fully round. Icon tiles use 28 % of their size.
- Shadows (`shadow-xs`, `shadow-card`, `shadow-raised`, `shadow-overlay`,
  `shadow-glow`, `shadow-highlight`) switch with the theme. The lip:
  `shadow-lip` (2 px `accent-edge` under Solar pills and the “+”),
  `shadow-lip-glow` (the same with the Solar glow, on hover) and
  `shadow-stack` (3 px darker bottom edge of stat tiles and category cards).
  Native: a 2 pt/dp bottom edge in `accentEdge` under Solar fills, a 3 pt/dp
  edge in `cardEdge` under stacked cards.
- Glass (`glass` utility: translucent surface, 24 px backdrop blur, light
  edge) only for the desktop window, floating bars and the mobile bottom bar.
  Text on glass must still pass contrast against the darkest/lightest
  wallpaper it can sit on; keep body text on solid surfaces.

## Motion

Durations 80 / 140 / 200 / 320 / 480 ms; `standard` easing for most changes,
`emphasized` for things entering (dialogs, sheets), springs on native
(existing `PassboxMotion` on Android, `Animation.timingCurve` on iOS). Every
platform honors reduced motion: CSS disables animations under
`prefers-reduced-motion`, `DesignTokens.Motion.standard(reduceMotion:)`
returns no animation, Compose code checks the animator duration scale.

## Layers

`--pb-z-*`: sticky 10, header 20, dropdown 30, scrim 40, modal 50, popover 60
(menus inside dialogs), toast 70, tooltip 80. Tailwind: `z-(--pb-z-modal)`.

## Tokens

<!-- @generated tokens:start — Generated by scripts/generate-design-tokens.mjs from packages/ui/tokens/tokens.json. Do not edit. -->
| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `canvas` | `0.974 0.005 90` #F8F6F3 | `0.205 0.022 232` #0C1920 | App and page background (light: warm paper; dark: deep Marina) |
| `surface` | `1 0 0` #FFFFFF | `0.255 0.028 232` #14252E | Surface 1: cards, panels, list columns |
| `surface-raised` | `0.962 0.006 231` #EFF3F6 | `0.295 0.033 232` #1B303A | Surface 2: hover rows, nested cards, dialog footers |
| `surface-overlay` | `1 0 0` #FFFFFF | `0.3487 0.0392 231.13` #243E4B | Surface 3: menus, popovers, dialogs, sheets (dark: Nocturnal Marina) |
| `field` | `1 0 0` #FFFFFF | `0.23 0.025 232` #101F27 | Text field and search background |
| `surface-sunken` | `0.948 0.008 231` #E9EFF2 | `0.178 0.02 232` #081318 | Wells: segmented-control tracks, code blocks, input groups |
| `surface-inverse` | `0.255 0.032 231` #11262F | `0.96 0.006 231` #EEF3F5 | Tooltips and inverse chips |
| `hairline` | `0.255 0.032 231 / 0.09` #11262F @ 9 % | `1 0 0 / 0.08` #FFFFFF @ 8 % | Dividers and glass edges (translucent) |
| `border` | `0.905 0.01 231` #D9E1E5 | `0.36 0.035 232` #2A414C | Card and control borders |
| `border-strong` | `0.85 0.014 231` #C5D0D5 | `0.44 0.04 231` #3B5765 | Input borders, emphasized outlines |
| `card-edge` | `0.87 0.014 231` #CBD6DC | `0.15 0.02 232` #040D12 | The lip under stacked cards: 3 px bottom edge of stat tiles and category cards |
| `text` | `0.255 0.032 231` #11262F | `0.97 0.006 231` #F1F6F8 | Primary text (light: Marina ink) |
| `text-muted` | `0.45 0.03 231` #455963 | `0.83 0.02 231` #BBCAD2 | Secondary text (alias: text-secondary) |
| `text-subtle` | `0.515 0.026 231` #596B74 | `0.76 0.025 231` #A2B4BE | Muted text: captions, placeholders, meta |
| `text-inverse` | `0.97 0.006 231` #F1F6F8 | `0.255 0.032 231` #11262F | Text on surface-inverse |
| `accent` | `0.9144 0.1396 95.56` #FFE26D | `0.9144 0.1396 95.56` #FFE26D | Solar Silk fill: primary buttons, the raised “+”, key highlights (always with accent-contrast ink) |
| `accent-hover` | `0.885 0.15 92` #FDD554 | `0.935 0.105 97` #FDEA97 | Hover on accent fills |
| `accent-pressed` | `0.842 0.1503 87.19` #F5C443 | `0.842 0.1503 87.19` #F5C443 | Pressed accent fills (the Solar lip) |
| `accent-edge` | `0.64 0.13 75` #BA7F14 | `0.78 0.15 82` #E7AC2A | The lip under accent fills: 2 px bottom edge of primary pills and the “+” |
| `accent-soft` | `0.945 0.02 228` #E0F0F8 | `0.38 0.052 229` #214858 | Sky-tinted backgrounds: badges, chips, icon tiles |
| `accent-contrast` | `0.255 0.032 231` #11262F | `0.255 0.032 231` #11262F | Text and icons on accent (Marina ink, never white) |
| `accent-text` | `0.46 0.08 232` #1E5F7D | `0.9144 0.1396 95.56` #FFE26D | Links and accent text on canvas and surfaces (Tailwind `text-accent`; light: deep Sky, dark: Solar) |
| `focus` | `0.3487 0.0392 231.13` #243E4B | `0.9144 0.1396 95.56` #FFE26D | Focus ring (light: Marina, dark: Solar) |
| `selection` | `0.915 0.03 229` #CFE7F3 | `0.365 0.05 229` #1F4353 | Selected list rows, active navigation, selected tabs (Sky tint) |
| `selection-marker` | `0.3487 0.0392 231.13` #243E4B | `0.9144 0.1396 95.56` #FFE26D | Marker bar and icon of the selected row or nav item |
| `control` | `0.3487 0.0392 231.13` #243E4B | `0.9144 0.1396 95.56` #FFE26D | Checked controls: switch tracks, checkboxes, radios, progress |
| `control-contrast` | `1 0 0` #FFFFFF | `0.255 0.032 231` #11262F | Thumb and check mark on control |
| `success` | `0.53 0.125 155` #13804A | `0.72 0.15 155` #43C07A | Success icons, bars, fills |
| `success-text` | `0.46 0.11 155` #0A693C | `0.82 0.13 155` #79DD9F | Success text |
| `success-soft` | `0.955 0.035 155` #DFF8E6 | `0.31 0.055 160` #123927 | Success backgrounds |
| `success-contrast` | `1 0 0` #FFFFFF | `0.16 0.03 155` #031108 | Text on success fills |
| `warning` | `0.7 0.17 50` #EF7926 | `0.74 0.16 52` #F88A3D | Warning icons, bars, the orange update banner (orange, never Solar yellow) |
| `warning-text` | `0.5 0.13 48` #9C470D | `0.82 0.12 58` #FEB073 | Warning text |
| `warning-soft` | `0.965 0.025 72` #FEF1E2 | `0.32 0.06 50` #4B2915 | Warning backgrounds |
| `warning-contrast` | `0.2 0.05 45` #280D02 | `0.2 0.05 45` #280D02 | Text on warning fills (ink, not white, for AA) |
| `danger` | `0.56 0.2 25` #D02B31 | `0.58 0.2 25` #D73337 | Danger icons and fills (destructive buttons) |
| `danger-text` | `0.52 0.19 25` #BE222A | `0.8 0.1 22` #F8A4A1 | Danger text |
| `danger-soft` | `0.96 0.019 25` #FFEDEB | `0.32 0.07 25` #512320 | Danger backgrounds |
| `danger-contrast` | `1 0 0` #FFFFFF | `1 0 0` #FFFFFF | Text on danger fills |
| `info` | `0.56 0.085 232` #397D9E | `0.7101 0.0751 228.76` #6EABC7 | Info icons (Sky Horizon) |
| `info-text` | `0.47 0.08 232` #216280 | `0.85 0.055 228` #A9D6EA | Info text |
| `info-soft` | `0.955 0.022 228` #E2F3FC | `0.33 0.045 230` #1A3A48 | Info backgrounds |
| `scrim` | `0.255 0.032 231 / 0.45` #11262F @ 45 % | `0.12 0.02 232 / 0.72` #01070C @ 72 % | Behind dialogs and sheets |
| `glass` | `1 0 0 / 0.72` #FFFFFF @ 72 % | `0.25 0.028 232 / 0.7` #13242D @ 70 % | Desktop window and floating bars (with backdrop blur) |
| `glass-border` | `1 0 0 / 0.7` #FFFFFF @ 70 % | `1 0 0 / 0.1` #FFFFFF @ 10 % | Edge of glass surfaces |
| `icon-tile` | `1 0 0` #FFFFFF | `0.95 0.004 231` #ECEFF1 | Tile behind favicons (light in both themes so dark marks stay visible) |
| `icon-tile-ring` | `0.255 0.032 231 / 0.08` #11262F @ 8 % | `1 0 0 / 0.06` #FFFFFF @ 6 % | Inner ring of favicon tiles |

Aliases: `surface-1` → `surface`, `surface-2` → `surface-raised`, `surface-3` → `surface-overlay`, `text-primary` → `text`, `text-secondary` → `text-muted`, `text-tertiary` → `text-subtle`.

Brand colors (`palette`, theme independent): `marina` #243E4B, `marina-lip` #0B1A21, `solar` #FFE26D, `solar-lip` #F5C443, `sky` #6EABC7, `sky-lip` #44739A, `glow-sky` rgba(110, 171, 199, 0.45), `glow-solar` rgba(255, 226, 109, 0.1).

Brand scale (Marina to Sky, theme independent): `50` #F0F8FC, `100` #DBEFF9, `200` #BADEEF, `300` #92C7DF, `400` #6EABC7, `500` #548FAB, `600` #417691, `700` #36596A, `800` #243E4B, `900` #12232B, `950` #0B1A21.

Category dots (`tag-*`, theme independent): `blue` #3F90DD, `violet` #8F6CE0, `pink` #EA5DA9, `red` #ED4A49, `orange` #F18336, `yellow` #F0CF4C, `green` #4AC06C, `teal` #35B9C0.

### Checked contrast pairs

| Foreground | Background | Target | Light | Dark |
| --- | --- | --- | --- | --- |
| `text` | `canvas` | 7:1 | 14.55 | 16.40 |
| `text` | `surface-overlay` | 7:1 | 15.68 | 10.33 |
| `text-muted` | `canvas` | 4.5:1 | 6.85 | 10.63 |
| `text-muted` | `surface-overlay` | 4.5:1 | 7.38 | 6.70 |
| `text-muted` | `surface-sunken` | 4.5:1 | 6.35 | 11.20 |
| `text-subtle` | `canvas` | 4.5:1 | 5.18 | 8.37 |
| `text-subtle` | `surface` | 4.5:1 | 5.59 | 7.35 |
| `text-subtle` | `surface-raised` | 4.5:1 | 5.01 | 6.46 |
| `text-subtle` | `field` | 4.5:1 | 5.59 | 7.88 |
| `text` | `field` | 7:1 | 15.68 | 15.45 |
| `text-inverse` | `surface-inverse` | 7:1 | 14.39 | 13.98 |
| `accent-contrast` | `accent` | 4.5:1 | 12.21 | 12.21 |
| `accent-contrast` | `accent-hover` | 4.5:1 | 11.09 | 13.02 |
| `accent-contrast` | `accent-pressed` | 4.5:1 | 9.60 | 9.60 |
| `accent-text` | `canvas` | 4.5:1 | 6.49 | 13.91 |
| `accent-text` | `surface` | 4.5:1 | 7.00 | 12.22 |
| `accent-text` | `surface-raised` | 4.5:1 | 6.27 | 10.73 |
| `accent-text` | `surface-overlay` | 4.5:1 | 7.00 | 8.77 |
| `accent-text` | `accent-soft` | 4.5:1 | 5.98 | 7.69 |
| `accent-text` | `selection` | 4.5:1 | 5.47 | 8.18 |
| `focus` | `canvas` | 3:1 | 10.44 | 13.91 |
| `focus` | `surface` | 3:1 | 11.26 | 12.22 |
| `focus` | `surface-overlay` | 3:1 | 11.26 | 8.77 |
| `accent-edge` | `surface` | 3:1 | 3.44 | 7.74 |
| `text` | `selection` | 7:1 | 12.27 | 9.65 |
| `text-muted` | `selection` | 4.5:1 | 5.77 | 6.25 |
| `selection-marker` | `selection` | 3:1 | 8.81 | 8.18 |
| `control` | `surface` | 3:1 | 11.26 | 12.22 |
| `control` | `surface-raised` | 3:1 | 10.09 | 10.73 |
| `control-contrast` | `control` | 4.5:1 | 11.26 | 12.21 |
| `border-strong` | `surface` | 1.4:1 | 1.58 | 2.04 |
| `success-text` | `success-soft` | 4.5:1 | 5.99 | 7.74 |
| `success-text` | `surface` | 4.5:1 | 6.75 | 9.45 |
| `success-contrast` | `success` | 4.5:1 | 4.97 | 8.29 |
| `success` | `surface` | 3:1 | 4.97 | 6.74 |
| `warning-text` | `warning-soft` | 4.5:1 | 5.70 | 7.20 |
| `warning-text` | `surface` | 4.5:1 | 6.32 | 8.74 |
| `warning-contrast` | `warning` | 4.5:1 | 6.46 | 7.55 |
| `warning` | `surface` | 2.2:1 | 2.83 | 6.48 |
| `danger-text` | `danger-soft` | 4.5:1 | 5.38 | 6.72 |
| `danger-text` | `surface` | 4.5:1 | 6.08 | 8.07 |
| `danger-contrast` | `danger` | 4.5:1 | 5.15 | 4.74 |
| `danger` | `surface` | 3:1 | 5.15 | 3.31 |
| `info-text` | `info-soft` | 4.5:1 | 5.90 | 7.74 |
| `info-text` | `surface` | 4.5:1 | 6.70 | 10.05 |
| `info` | `surface` | 3:1 | 4.56 | 6.21 |

### Type scale

| Step | Size (px/pt/sp) | Line height | Tracking | Weight | iOS Dynamic Type | Use |
| --- | --- | --- | --- | --- | --- | --- |
| `display-xl` | 72 | 1 | -0.035 em | 600 | `.largeTitle` | Website hero |
| `display` | 56 | 1.04 | -0.03 em | 600 | `.largeTitle` | Website section titles |
| `display-sm` | 44 | 1.08 | -0.028 em | 600 | `.largeTitle` | Website sub-hero, big stats |
| `title-lg` | 34 | 1.12 | -0.022 em | 700 | `.largeTitle` | Mobile large titles, onboarding |
| `title` | 28 | 1.18 | -0.02 em | 600 | `.title` | Page titles (web app), sheet titles |
| `title-sm` | 22 | 1.25 | -0.015 em | 600 | `.title2` | Item detail title, dialog titles on mobile |
| `headline` | 18 | 1.35 | -0.01 em | 600 | `.headline` | Card titles, section headers |
| `body-lg` | 16 | 1.5 | 0 em | 400 | `.body` | Marketing body, mobile body |
| `body` | 14 | 1.45 | 0 em | 400 | `.subheadline` | App body text (web base size) |
| `body-sm` | 13 | 1.4 | 0 em | 400 | `.footnote` | Dense lists, secondary lines |
| `label` | 13 | 1.25 | 0 em | 600 | `.footnote` | Buttons, field labels, tabs |
| `label-sm` | 12 | 1.2 | 0.01 em | 600 | `.caption` | Small buttons, pills |
| `caption` | 12 | 1.35 | 0 em | 400 | `.caption` | Meta text, timestamps |
| `overline` | 11 | 1.2 | 0.08 em | 700 (uppercase) | `.caption2` | Section eyebrows, POPULAR pill |
| `stat` | 40 | 1 | -0.03 em | 700 (tabular nums) | `.largeTitle` | Big numbers in stat tiles |
| `mono` | 13 | 1.5 | 0 em | 500 (mono) | `.footnote` | Passwords, codes, keys |

### Gradients

- `signature` (135°): #36596A 0 % → #243E4B 50 % → #12232B 100 %. The Passbox gradient: logo tile, app icons, brand panels. Lighter Marina top-left into Nocturnal Marina into deep Marina (#36596A → #243E4B → #12232B).
- `backdrop` (180°): #123847 0 % → #0D1D25 42 % → #061016 100 %. Website and onboarding backdrop behind panels: deep Marina, lighter towards the top; add the Sky glow (top), the soft Solar glow and grain.

### Radii

| Token | Value | Use |
| --- | --- | --- |
| `xs` | 6 px | Kbd, tiny chips (Tailwind `rounded-md`) |
| `sm` | 8 px | Small controls, menu items (Tailwind `rounded-lg`) |
| `control` | 12 px | Buttons, inputs, list rows, favicon tiles (40 px) |
| `tile` | 16 px | Icon and category tiles: 28 % of the tile size (24 → 7, 32 → 9, 40 → 11, 56 → 16) |
| `card` | 20 px | Cards, dialogs, stat tiles |
| `panel` | 24 px | Desktop window, website device panels, large cards |
| `sheet` | 28 px | Bottom sheets, mobile cards |
| `pill` | full | Pills, pill buttons, switches, FAB |

### Spacing, motion, layers

- Spacing (4 px grid): `1` 4, `2` 8, `3` 12, `4` 16, `5` 20, `6` 24, `8` 32, `10` 40, `12` 48, `16` 64, `20` 80, `24` 96, `0.5` 2, `1.5` 6.
- Durations: `instant` 80 ms, `fast` 140 ms, `base` 200 ms, `slow` 320 ms, `slower` 480 ms.
- Easing: `standard` cubic-bezier(0.2, 0, 0, 1), `emphasized` cubic-bezier(0.16, 1, 0.3, 1), `decelerate` cubic-bezier(0, 0, 0, 1), `accelerate` cubic-bezier(0.3, 0, 1, 1).
- Layers (`--pb-z-*`): `base` 0, `raised` 1, `sticky` 10, `header` 20, `dropdown` 30, `scrim` 40, `modal` 50, `popover` 60, `toast` 70, `tooltip` 80.
<!-- @generated tokens:end -->

## Components

React components in `@passbox/ui` (`packages/ui/src`). Native apps build the
same anatomy from the tokens. Every interactive component has a visible
focus ring (`focus` token, 2 px, offset 2 px), a 44 px (iOS, touch web) or
48 dp (Android) target, and a disabled state at 50 % opacity.

| Component | Anatomy | States and rules |
| --- | --- | --- |
| `Button` | label, optional leading icon or spinner; `variant` primary / secondary / soft / ghost / subtle / danger / onAccent (icon buttons on a solid accent fill); `size` xs–lg, icon sizes; `shape="pill"` | Primary: Solar fill, Marina ink, the lip (`shadow-lip`); hover `accent-hover` + `shadow-lip-glow`; pressed `accent-pressed` without lip. `loading` disables and shows a spinner. Pill shape for calls to action and marketing; rounded (12 px) in app chrome. One primary button per view. |
| `IconButton` | icon only, required `label` (accessible name) | Ghost by default. |
| `Fab` | the raised round “+”: 56 px Solar circle with a Marina “+”, the lip and the Solar glow, a 4 px canvas-colored ring | One per screen, bottom right of the desktop/web item list (opens “New item”); the mobile bottom bar uses the same anatomy. Required `label`. |
| `Avatar` | round tile with up to two initials; `tone` tint (a hue per person) or signature (the signed-in account: Solar initials on the Marina gradient); sizes xs 24 / sm 32 / md 36 / lg 44 / xl 64 | People only (account card, unlock, “Shared with”, members); items use favicon tiles. Decorative: the name is always next to it. |
| `Input`, `PasswordInput`, `Textarea` | label, field (12 px radius, `field` background), hint or error below, leading/trailing slots | Focus: accent border + 4 px focus halo; error: danger border and `danger-text` message that says what happened and what to do. Password fields: mono, reveal toggle, Caps Lock hint. |
| `Field` | read-only item field: caption label, value, actions (reveal, copy, open) | Hairline divider; secrets in mono; actions are `IconButton`s with labels. |
| `SegmentedControl` | pill track (`surface-sunken`), selected pill on `surface-overlay` | Native radio inputs; arrow keys work. |
| `Switch` | 40 × 24 track, 20 px thumb | Track `control` when on with a `control-contrast` thumb (Marina/white in light, Solar/Marina in dark); always paired with a visible label. |
| `Badge` / `Pill` | pill, optional dot; tones neutral / accent / success / warning / danger / info; `variant` soft / solid / outline | Status only; never the only carrier of meaning (text always present). |
| `Card` | 20 px radius surface; `variant` default / raised / sunken / glass / outline; `padding` | `interactive` adds hover and focus. |
| `Panel` | 24 px radius large surface, optional bezel, optional forced `theme` | Website device panels (alternate light and dark on the backdrop), desktop window. |
| `GridFrame` | dotted vertical guides, dotted rule, corner dots | Decorative motif for panels and onboarding (see brand.md). |
| `Dialog`, `ConfirmDialog` | scrim (`scrim` + blur), card on `surface-overlay`, title, description, body, footer with hairline | Destructive confirmation uses `danger`; Escape and the close button dismiss. |
| `Sheet` | bottom sheet with grabber (mobile) or right side panel | Same semantics as `Dialog`; respects the safe area. |
| `Toaster` / `toast()` | overlay surface, icon, text, optional action pill | Says what happened and, for errors, what to do. |
| `Tabs` + `TabPanel` | underline (sections) or pill (filters), optional count | WAI-ARIA tabs: arrow keys, Home, End. |
| `Monogram`, `SiteIcon` (`ItemIcon`) | tile with favicon on a light tile, or a tinted initial | Sizes sm 24 / md 32 / lg 40 / xl 56 / 2xl 72; radius 28 % of the size. Always a real favicon or brand icon when available. |
| `StatTile` | tone chip (icon) or dot, big tabular number, label, optional detail | Security report: Compromised (danger), Reused (warning), Weak (warning), Safe (success). Tone only in the chip, the number stays `text`. `interactive` makes it a filter button. |
| `AlertCard` | `card`: icon tile, title, description, action; `banner`: solid strip with action (the orange “Time to change your password · Change now”) | Danger and warning use `role="alert"`, others `role="status"`; optional dismiss. |
| `EmptyState` | `brand` (default): the Solar icon on the Marina signature gradient inside two dotted rings with corner dots (the panel motif in miniature) and a soft glow; `quiet`: an accent-soft tile; title, description, action | Every list has one; it says what to do next. `quiet` for searches without results and small inline lists. |
| `Skeleton` | shimmering placeholder shape | Hidden from screen readers; the region sets `aria-busy`. Shimmer stops with reduced motion. |
| `SidebarItem` | icon or colored category dot (`tag-*`), label, count | Active: `selection` fill with a `selection-marker` icon, `aria-current="page"`. `sidebarItemClassName` for router links. |
| `ListRow` | icon tile, title (service), subtitle (username), trailing (shield badge, time) | Selected = `selection` fill (Sky tint) with a 3 px `selection-marker` bar at the leading edge and normal text colours; hover = `surface-raised`. `listRowClassName` for router links. |
| `Menu`, `Tooltip`, `Kbd`, `Spinner`, `StrengthMeter`, `Logo` | as before, restyled | Menus on `surface-overlay` at the popover layer; tooltips inverse. |

### Mobile patterns (iOS and Android)

- Large title (`title-lg`, 34) at the top of each tab; search as a pill.
- Home: 2 × 2 category cards (`sheet` radius on mobile, outline icon, title,
  count, chevron), then “Recently used” with round favicon tiles.
- Bottom bar: floating glass bar with four outline icons and a raised round
  “+” in the middle in Solar with a Marina “+” (56–60 pt, the lip, a soft
  Solar glow, a canvas-colored ring separates it from the bar). It opens
  “New item”. The selected tab icon uses `selection-marker`.
- Category cards and stat tiles are stacked cards with the 3 pt/dp lip.
- Security: score ring, alert card, 2 × 2 `StatTile`s.

### Desktop and web vault

Three columns on the app canvas (`bg-app`: the canvas with a soft Sky glow
top left and a faint Solar glow bottom right). The sidebar (`surface` at 70 % with backdrop blur) has
the account card (Marina avatar with Solar initials, email, family or team), the sections
All items / Favorites / Security check / Family & team / Trash
with counts, categories, vaults with colored dots (`vaultColor`: the personal
vault `tag-blue`, others a stable color per vault), tools, the sync state and the
full-width Solar “New item +” pill at the bottom. The item list (glass) has a
44 px search field, rows with 40 px favicon tiles, the selected row in the Sky
selection tint with its marker (on phones only once the user opened an item), a shield
badge on rows with findings, and the raised round “+” (`Fab`). The detail
(`surface` at 85 %) shows the 56 px icon tile, the title with a category
pill and a vault chip, the actions favourite / edit / share / more, the
orange banner “Time to change your password · Change now” with the
reasons below it, field cards with always visible reveal and copy buttons,
the one-time password with its countdown ring, “Shared with” with avatars
and the metadata. Pages without a list (settings, security check,
generator, sharing, developer tools, import) use `Page` and `Panel` in
`app/src/views/PageHeader.tsx` (passboxnet/web): an eyebrow, the `title` step, cards
with icon tiles; the same anatomy as the admin consoles. Sign-up, sign-in,
unlock and the Emergency Kit sit on the backdrop gradient with grain in a
bezelled `Panel` (dark brand half with `GridFrame` next to the form).

In the desktop app on Windows 11 the window uses the Mica material and the
canvas becomes translucent (`html[data-window-material="mica"]`); elsewhere
the canvas stays solid (see [desktop.md](https://github.com/passboxnet/desktop/blob/main/docs/desktop.md)).

## Iconography

One outline family everywhere: Lucide, 24 × 24, 2 px stroke, round caps and
joins (`lucide-react` on the web; generated asset catalog and vector
drawables on iOS and Android, see brand.md). 16 px in dense controls, 20 px in
list rows and cards, 24 px in bars. Filled icons only for the selected state
of a bottom bar item, if at all. Status icons: `shield-alert` (compromised),
`copy` (reused), `triangle-alert` (weak), `shield-check` (safe).

## Imagery and illustration

- No stock photos of people, no mascots. Use abstract, geometric
  illustration: the keyhole mark, rounded tiles, rings, dotted grids, and the
  signature/backdrop gradients with soft grain.
- Product screenshots and mocks show realistic but invented data (no real
  people's names with real accounts, no customer logos).
- Website social proof (testimonials, logos, certifications) only from real
  sources; placeholders are marked as such and never shipped.
- Illustrations must work in both themes: draw them with token colors or
  provide a light and a dark version.

## Do and don't

| Do | Don't |
| --- | --- |
| One Solar primary action per view | Several competing yellow buttons, or Solar as decoration |
| Marina ink on Solar | White text on Solar, Solar text on white |
| Sky tint for selection | Full Solar fill for selected rows |
| Orange for warnings | Yellow (Solar-like) for warnings |
| Lighter surfaces for elevation in dark mode | Heavy black drop shadows |
| `text-accent` (text variant) for links | Accent fill color for small text on dark surfaces |
| Status colors only for status | Orange or red for decoration |
| Real favicons in rounded tiles | Generic globe icons when an icon is available |
| Hairline borders, generous radii | Thick borders, sharp corners on cards |
| The Marina signature gradient on the mark, app icons and brand panels | Gradient behind body text or on every card |
| Tabular numbers in stats and codes | Proportional digits that jump while counting |

## Accessibility

- WCAG 2.2 AA in both themes. The generator fails if a declared pair drops
  below its target (table above): 4.5:1 for text, 3:1 for focus rings, icons
  and fills that identify state, 7:1 for primary text.
- Focus is always visible (`focus` token, 2 px). Never remove outlines
  without a replacement.
- Targets: 44 × 44 pt (iOS, coarse pointers on the web via `coarse:`), 48 × 48
  dp (Android).
- Text scales: Dynamic Type on iOS, `sp` on Android, rem on the web; layouts
  reflow instead of truncating important content.
- Reduced motion: no parallax, shimmer or springs; instant state changes.
- Color is never the only signal: badges carry text, risky rows carry an
  icon with an accessible label.
- German uses “Sie”; every string exists in English and German.
