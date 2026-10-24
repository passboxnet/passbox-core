# UI guidelines

Passbox should look and feel like world-class enterprise software: calm, dense where it helps, fast, and trustworthy. Reference points: Linear, Vercel, Stripe Dashboard, 1Password 8.

## Foundations

- **Design system:** `@passbox/ui` (React, Tailwind CSS v4 tokens, Radix primitives). Use its components and semantic tokens; do not hard-code colors.
- **Fonts:** Inter Variable for UI, JetBrains Mono Variable for secrets, codes and keys. Both self-hosted via `@passbox/ui/fonts.css`. No third-party font or asset requests.
- **Color:** neutral, cool grays with one brand blue (`accent`). Status colors (`success`, `warning`, `danger`) only for status. Use the `*-soft` variants for backgrounds of badges and banners.
- **Theme:** every surface works in light and dark. Never use Tailwind's `dark:` variant; the semantic tokens switch automatically (also when `data-theme` is forced).
- **Type scale:** 13–14 px body text in the app, 11 px (`text-2xs`) for meta labels, 20–24 px page titles. Marketing pages may go larger (48–64 px hero).
- **Spacing and shape:** 4 px grid. Radius 6–8 px for controls, 12 px (`rounded-card`) for cards and dialogs. 1 px borders (`border-border`), very soft shadows (`shadow-xs`, `shadow-card`, `shadow-overlay` for popovers).
- **Icons:** lucide-react, 16 px in controls, stroke width default.

## Behavior

- Keyboard first: visible focus rings, shortcuts for frequent actions (shown with `Kbd`), command palette (⌘K / Ctrl+K) in the app.
- Every list has an empty state (`EmptyState`) that explains what to do next.
- Feedback through toasts (`toast()`), not alerts. Destructive actions use `ConfirmDialog`.
- Loading: buttons show `loading`; long operations explain what happens ("Deriving your keys on this device…").
- Copying secrets shows a toast and clears the clipboard after 90 seconds.
- Respect `prefers-reduced-motion`. Animations are short (≤ 150 ms) and subtle.
- Accessibility: WCAG 2.2 AA. Labels on every control, `aria-*` on icon-only buttons, sufficient contrast in both themes.

## Honesty

Marketing copy must not claim features that do not exist yet, invent customers, logos, testimonials, certifications or numbers. Label planned features as "Coming soon" or "On the roadmap".
