# Passbox design system ("Passbox Night")

The visual language of every Passbox surface: website, web app, desktop app,
browser extension, iOS, Android and the server's own pages and emails. The
brand elements (logo, app icons, gradient, motif, icon family) are in
[brand.md](brand.md); the visual board is [board.html](board.html) (open it in
a browser; screenshots in both themes are attached to the redesign PRs).

**Direction:** dark-first, premium and calm. Deep ink surfaces, one electric
blue, generous radii, hairline borders, elevation through lighter surfaces
rather than heavy shadows, and a light theme designed with the same care (not
an inversion). The system default theme is respected everywhere.

## Sources and outputs

One source, generated everywhere:

| What | Where |
| --- | --- |
| Token source (colors, type, radii, spacing, motion, layers, gradients) | `packages/ui/tokens/tokens.json` |
| Generator and checks (sRGB gamut, WCAG contrast, stale outputs) | `scripts/generate-design-tokens.mjs` (`pnpm --filter @passbox/ui tokens`; `pnpm test` runs `--check`) |
| Web, extension, desktop, website | `packages/ui/src/tokens.css` (Tailwind CSS v4 `@theme` + CSS variables `--pb-*`) |
| iOS | `apps/ios/Shared/DesignTokens.swift` (dynamic light/dark colors without asset catalog entries, type scale, radii, spacing, motion, gradients) |
| Android | `apps/android/app/src/main/java/dev/passbox/android/ui/theme/Tokens.kt` (Material `ColorScheme` light/dark, `PassboxColors`, `PassboxTokenTypography`, `PassboxShapeScale`, spacing, motion, gradients) |
| Server pages and emails | `crates/server/src/brand/tokens.rs` (sRGB colors per theme, gradients, font stacks, radii) |
| Logo, app icons, icon family | `scripts/generate-brand-assets.mjs`, see [brand.md](brand.md) |

Change a value in `tokens.json`, run `node scripts/generate-design-tokens.mjs`
and commit every changed file. Never edit generated regions by hand.

## Typography

- **Sans:** Plus Jakarta Sans (SIL Open Font License 1.1), a geometric sans with
  tabular figures, `case` forms and full Latin Extended (German, Polish,
  Vietnamese …). Web: `@fontsource-variable/plus-jakarta-sans` (variable
  200–800) via `@passbox/ui/fonts.css`, bundled by Vite and Next.js, no font
  CDN. iOS: static TTFs in `apps/ios/Shared/Fonts` (registered with
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
  use the fill. Text on a fill uses `*-contrast` (white, except ink on the
  orange warning fill).
- **Elevation is lightness.** In dark mode surfaces get lighter as they rise
  (canvas → surface → surface-raised → surface-overlay); shadows are subtle
  and add a 1 px top highlight. In light mode surfaces are white on an
  off-white canvas with soft shadows.

`data-theme="light"` or `data-theme="dark"` works on `<html>` (forced theme)
and on any element (a light website panel on a dark page).

## Shape, space and elevation

- 4 px spacing grid (Tailwind's default spacing scale).
- Radii: controls 12 px, cards 20 px, panels and windows 24 px, sheets 28 px,
  pills and switches fully round. Icon tiles use 28 % of their size.
- Shadows (`shadow-xs`, `shadow-card`, `shadow-raised`, `shadow-overlay`,
  `shadow-glow`, `shadow-highlight`) switch with the theme.
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
| `canvas` | `0.975 0.004 266` #F5F7FA | `0.145 0.022 266` #060A13 | App and page background |
| `surface` | `1 0 0` #FFFFFF | `0.195 0.026 266` #0F1521 | Surface 1: cards, panels, list columns |
| `surface-raised` | `0.968 0.006 266` #F2F4F9 | `0.235 0.028 266` #181E2B | Surface 2: hover rows, nested cards, dialog footers |
| `surface-overlay` | `1 0 0` #FFFFFF | `0.27 0.03 266` #1F2635 | Surface 3: menus, popovers, dialogs, sheets |
| `field` | `1 0 0` #FFFFFF | `0.165 0.024 266` #090E19 | Text field and search background |
| `surface-sunken` | `0.955 0.007 266` #EEF0F5 | `0.125 0.02 266` #04060E | Wells: segmented-control tracks, code blocks, input groups |
| `surface-inverse` | `0.2 0.03 266` #101624 | `0.96 0.006 266` #F0F2F6 | Tooltips and inverse chips |
| `hairline` | `0.2 0.03 266 / 0.08` #101624 @ 8 % | `1 0 0 / 0.08` #FFFFFF @ 8 % | Dividers and glass edges (translucent) |
| `border` | `0.915 0.008 266` #E0E3E8 | `0.3 0.03 266` #272E3D | Card and control borders |
| `border-strong` | `0.855 0.012 266` #CCCFD7 | `0.38 0.032 266` #3A4254 | Input borders, emphasized outlines |
| `text` | `0.19 0.03 266` #0D1321 | `0.97 0.006 266` #F3F5F9 | Primary text |
| `text-muted` | `0.45 0.025 266` #4F5564 | `0.79 0.02 266` #B4BBC8 | Secondary text (alias: text-secondary) |
| `text-subtle` | `0.515 0.02 266` #626773 | `0.7 0.022 266` #989EAD | Muted text: captions, placeholders, meta |
| `text-inverse` | `0.97 0.006 266` #F3F5F9 | `0.19 0.03 266` #0D1321 | Text on surface-inverse |
| `accent` | `0.54 0.225 263` #1F5FEE | `0.57 0.215 262` #276CF3 | Electric blue fill: primary buttons, selected rows, switches |
| `accent-hover` | `0.49 0.215 263` #1550D7 | `0.535 0.22 262` #185FEA | Hover on accent fills |
| `accent-pressed` | `0.45 0.2 263` #1046C1 | `0.5 0.21 262` #1256D8 | Pressed accent fills |
| `accent-soft` | `0.945 0.026 263` #E4EDFF | `0.3 0.085 263` #162B58 | Tinted backgrounds: badges, selected chips, icon tiles |
| `accent-contrast` | `1 0 0` #FFFFFF | `1 0 0` #FFFFFF | Text and icons on accent |
| `accent-text` | `0.52 0.22 263` #1C59E4 | `0.76 0.12 258` #80B3FD | Links and accent text on canvas and surfaces (Tailwind `text-accent`) |
| `focus` | `0.54 0.225 263` #1F5FEE | `0.72 0.14 260` #6FA4FC | Focus ring |
| `success` | `0.53 0.125 155` #13804A | `0.7 0.15 155` #3BB974 | Success icons, bars, fills |
| `success-text` | `0.46 0.11 155` #0A693C | `0.8 0.14 155` #6AD895 | Success text |
| `success-soft` | `0.955 0.035 155` #DFF8E6 | `0.27 0.055 155` #0B2E1A | Success backgrounds |
| `success-contrast` | `1 0 0` #FFFFFF | `0.16 0.03 155` #031108 | Text on success fills |
| `warning` | `0.72 0.165 58` #EF861B | `0.75 0.16 60` #F6922E | Warning icons, bars, the orange update banner |
| `warning-text` | `0.49 0.12 55` #924A03 | `0.83 0.13 72` #FBB961 | Warning text |
| `warning-soft` | `0.965 0.027 75` #FFF1E0 | `0.29 0.06 60` #412307 | Warning backgrounds |
| `warning-contrast` | `0.2 0.05 50` #270E01 | `0.2 0.05 50` #270E01 | Text on warning fills (ink, not white, for AA) |
| `danger` | `0.56 0.2 25` #D02B31 | `0.58 0.2 25` #D73337 | Danger icons and fills (destructive buttons) |
| `danger-text` | `0.52 0.19 25` #BE222A | `0.76 0.14 22` #FE8A88 | Danger text |
| `danger-soft` | `0.96 0.019 25` #FFEDEB | `0.28 0.075 25` #471715 | Danger backgrounds |
| `danger-contrast` | `1 0 0` #FFFFFF | `1 0 0` #FFFFFF | Text on danger fills |
| `info` | `0.58 0.1 235` #3383AD | `0.72 0.11 230` #50B1DC | Info icons |
| `info-text` | `0.48 0.09 235` #1C6589 | `0.82 0.09 230` #85CFF3 | Info text |
| `info-soft` | `0.96 0.02 235` #E6F4FE | `0.28 0.05 235` #0A2C3E | Info backgrounds |
| `scrim` | `0.2 0.03 266 / 0.45` #101624 @ 45 % | `0.08 0.02 266 / 0.7` #010205 @ 70 % | Behind dialogs and sheets |
| `glass` | `1 0 0 / 0.72` #FFFFFF @ 72 % | `0.2 0.03 266 / 0.68` #101624 @ 68 % | Desktop window and floating bars (with backdrop blur) |
| `glass-border` | `1 0 0 / 0.7` #FFFFFF @ 70 % | `1 0 0 / 0.1` #FFFFFF @ 10 % | Edge of glass surfaces |
| `icon-tile` | `1 0 0` #FFFFFF | `0.95 0.004 266` #EDEEF1 | Tile behind favicons (light in both themes so dark marks stay visible) |
| `icon-tile-ring` | `0.19 0.03 266 / 0.08` #0D1321 @ 8 % | `1 0 0 / 0.06` #FFFFFF @ 6 % | Inner ring of favicon tiles |

Aliases: `surface-1` → `surface`, `surface-2` → `surface-raised`, `surface-3` → `surface-overlay`, `text-primary` → `text`, `text-secondary` → `text-muted`, `text-tertiary` → `text-subtle`.

Brand scale (theme independent): `50` #F0F5FE, `100` #DFEAFE, `200` #BED5FE, `300` #91B8FD, `400` #5E95FD, `500` #3376FB, `600` #1F5FEE, `700` #164DC8, `800` #153A99, `900` #102766, `950` #071335.

Category dots (`tag-*`, theme independent): `blue` #3E89F7, `violet` #9167EA, `pink` #ED58A9, `red` #ED4A49, `orange` #EF852E, `yellow` #F3C530, `green` #4AC06C, `teal` #16BBBC.

### Checked contrast pairs

| Foreground | Background | Target | Light | Dark |
| --- | --- | --- | --- | --- |
| `text` | `canvas` | 7:1 | 17.20 | 18.16 |
| `text` | `surface-overlay` | 7:1 | 18.49 | 13.84 |
| `text-muted` | `canvas` | 4.5:1 | 6.93 | 10.24 |
| `text-muted` | `surface-overlay` | 4.5:1 | 7.45 | 7.80 |
| `text-muted` | `surface-sunken` | 4.5:1 | 6.53 | 10.45 |
| `text-subtle` | `canvas` | 4.5:1 | 5.24 | 7.41 |
| `text-subtle` | `surface` | 4.5:1 | 5.63 | 6.85 |
| `text-subtle` | `surface-raised` | 4.5:1 | 5.13 | 6.24 |
| `text-subtle` | `field` | 4.5:1 | 5.63 | 7.21 |
| `text` | `field` | 7:1 | 18.49 | 17.68 |
| `text-inverse` | `surface-inverse` | 7:1 | 16.62 | 16.46 |
| `accent-contrast` | `accent` | 4.5:1 | 5.34 | 4.65 |
| `accent-contrast` | `accent-hover` | 4.5:1 | 6.62 | 5.43 |
| `accent-contrast` | `accent-pressed` | 4.5:1 | 7.84 | 6.30 |
| `accent-text` | `canvas` | 4.5:1 | 5.41 | 9.20 |
| `accent-text` | `surface-raised` | 4.5:1 | 5.30 | 7.76 |
| `accent-text` | `accent-soft` | 4.5:1 | 4.95 | 6.40 |
| `focus` | `canvas` | 3:1 | 4.97 | 7.92 |
| `focus` | `surface-overlay` | 3:1 | 5.34 | 6.04 |
| `accent` | `canvas` | 3:1 | 4.97 | 4.25 |
| `border-strong` | `surface` | 1.4:1 | 1.56 | 1.83 |
| `success-text` | `success-soft` | 4.5:1 | 5.99 | 8.35 |
| `success-text` | `surface` | 4.5:1 | 6.75 | 10.35 |
| `success-contrast` | `success` | 4.5:1 | 4.97 | 7.71 |
| `success` | `surface` | 3:1 | 4.97 | 7.31 |
| `warning-text` | `warning-soft` | 4.5:1 | 5.89 | 8.32 |
| `warning-text` | `surface` | 4.5:1 | 6.53 | 10.64 |
| `warning-contrast` | `warning` | 4.5:1 | 7.03 | 7.88 |
| `warning` | `surface` | 2.2:1 | 2.60 | 7.90 |
| `danger-text` | `danger-soft` | 4.5:1 | 5.38 | 6.59 |
| `danger-text` | `surface` | 4.5:1 | 6.08 | 8.04 |
| `danger-contrast` | `danger` | 4.5:1 | 5.15 | 4.74 |
| `danger` | `surface` | 3:1 | 5.15 | 3.86 |
| `info-text` | `info-soft` | 4.5:1 | 5.74 | 8.45 |
| `info-text` | `surface` | 4.5:1 | 6.42 | 10.69 |

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

- `signature` (135°): #5EA8F9 0 % → #2061F5 50 % → #1A2C94 100 %. The Passbox gradient: logo tile, app icons, primary hero accents. Sky blue top-left into electric blue into deep indigo.
- `backdrop` (180°): #040713 0 % → #061348 45 % → #2D54D3 100 %. Website and onboarding backdrop behind panels: deep navy into electric blue (add grain).

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
| `Button` | label, optional leading icon or spinner; `variant` primary / secondary / soft / ghost / subtle / danger; `size` xs–lg, icon sizes; `shape="pill"` | Hover darkens the fill and adds `shadow-glow` (primary); pressed uses `accent-pressed`; `loading` disables and shows a spinner. Pill shape for calls to action and marketing; rounded (12 px) in app chrome. One primary button per view. |
| `IconButton` | icon only, required `label` (accessible name) | Ghost by default; `shape="circle"` + primary + `lg` = the floating “+”. |
| `Input`, `PasswordInput`, `Textarea` | label, field (12 px radius, `field` background), hint or error below, leading/trailing slots | Focus: accent border + 4 px focus halo; error: danger border and `danger-text` message that says what happened and what to do. Password fields: mono, reveal toggle, Caps Lock hint. |
| `Field` | read-only item field: caption label, value, actions (reveal, copy, open) | Hairline divider; secrets in mono; actions are `IconButton`s with labels. |
| `SegmentedControl` | pill track (`surface-sunken`), selected pill on `surface-overlay` | Native radio inputs; arrow keys work. |
| `Switch` | 40 × 24 track, 20 px thumb | Track `accent` when on; always paired with a visible label. |
| `Badge` / `Pill` | pill, optional dot; tones neutral / accent / success / warning / danger / info; `variant` soft / solid / outline | Status only; never the only carrier of meaning (text always present). |
| `Card` | 20 px radius surface; `variant` default / raised / sunken / glass / outline; `padding` | `interactive` adds hover and focus. |
| `Panel` | 24 px radius large surface, optional bezel, optional forced `theme` | Website device panels (alternate light and dark on the backdrop), desktop window. |
| `GridFrame` | dotted vertical guides, dotted rule, corner dots | Decorative motif for panels and onboarding (see brand.md). |
| `Dialog`, `ConfirmDialog` | scrim (`scrim` + blur), card on `surface-overlay`, title, description, body, footer with hairline | Destructive confirmation uses `danger`; Escape and the close button dismiss. |
| `Sheet` | bottom sheet with grabber (mobile) or right side panel | Same semantics as `Dialog`; respects the safe area. |
| `Toaster` / `toast()` | overlay surface, icon, text, optional action pill | Says what happened and, for errors, what to do. |
| `Tabs` + `TabPanel` | underline (sections) or pill (filters), optional count | WAI-ARIA tabs: arrow keys, Home, End. |
| `Monogram`, `SiteIcon` (`ItemIcon`) | tile with favicon on a light tile, or a tinted initial | Sizes sm 24 / md 32 / lg 40 / xl 56 / 2xl 72; radius 28 % of the size. Always a real favicon or brand icon when available. |
| `StatTile` | tone chip (icon) or dot, big tabular number, label, optional detail | Security report: Gefährdet (danger), Mehrfach (warning), Schwach (warning), Sicher (success). Tone only in the chip, the number stays `text`. `interactive` makes it a filter button. |
| `AlertCard` | `card`: icon tile, title, description, action; `banner`: solid strip with action (the orange “Zeit, Ihr Passwort zu ändern · Jetzt ändern”) | Danger and warning use `role="alert"`, others `role="status"`; optional dismiss. |
| `EmptyState` | accent-soft icon tile, title, description, action | Every list has one; it says what to do next. |
| `Skeleton` | shimmering placeholder shape | Hidden from screen readers; the region sets `aria-busy`. Shimmer stops with reduced motion. |
| `SidebarItem` | icon or colored category dot (`tag-*`), label, count | Active: `surface-raised` with accent icon, `aria-current="page"`. `sidebarItemClassName` for router links. |
| `ListRow` | icon tile, title (service), subtitle (username), trailing (shield badge, time) | Selected = solid `accent` fill with white text and glow; hover = `surface-raised`. `listRowClassName` for router links. |
| `Menu`, `Tooltip`, `Kbd`, `Spinner`, `StrengthMeter`, `Logo` | as before, restyled | Menus on `surface-overlay` at the popover layer; tooltips inverse. |

### Mobile patterns (iOS and Android)

- Large title (`title-lg`, 34) at the top of each tab; search as a pill.
- Home: 2 × 2 category cards (`sheet` radius on mobile, outline icon, title,
  count, chevron), then “Zuletzt verwendet” with round favicon tiles.
- Bottom bar: floating glass bar with four outline icons and a raised round
  “+” in the middle on the signature gradient (56–60 pt, glow, a canvas-colored
  ring separates it from the bar). It opens “Neuer Eintrag”.
- Security: score ring, alert card, 2 × 2 `StatTile`s.

### Desktop and web vault

Three columns on a glass window (desktop app) or the canvas (web): sidebar
(account, sections, vaults with colored dots, full-width “Neuer Eintrag”
button at the bottom), item list (search with ⌘K hint, rows with 40 px icon
tiles, selected row solid blue, shield badge on risky rows), detail (56 px
icon tile, title, category pill, actions; inline warning banner; fields with
reveal and copy; one-time password with countdown ring; “Geteilt mit”).

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
  sources; placeholders are marked as such and never shipped (see
  docs/website.md once the website is rebuilt).
- Illustrations must work in both themes: draw them with token colors or
  provide a light and a dark version.

## Do and don't

| Do | Don't |
| --- | --- |
| One electric-blue primary action per view | Several competing blue buttons |
| Lighter surfaces for elevation in dark mode | Heavy black drop shadows |
| `text-accent` (text variant) for links | Accent fill color for small text on dark surfaces |
| Status colors only for status | Orange or red for decoration |
| Real favicons in rounded tiles | Generic globe icons when an icon is available |
| Hairline borders, generous radii | Thick borders, sharp corners on cards |
| The signature gradient on the mark, app icons, the “+” and hero accents | Gradient behind body text or on every card |
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
