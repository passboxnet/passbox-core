/**
 * Shared translations for the web app, desktop app and browser extension.
 *
 * Catalogs live in `messages/<locale>/<namespace>.json` as flat
 * `"dotted.key": "Message"` maps in ICU-style syntax (see `formatMessage`).
 * English is the source and the fallback. Every key must exist in every
 * locale; `catalogs.test.ts` enforces it. Terminology: see GLOSSARY.md.
 */
import { formatMessage, type Params } from "./format";

export { formatMessage, type Params } from "./format";

export const LOCALES = ["en", "de"] as const;
export type Locale = (typeof LOCALES)[number];

export const LOCALE_NAMES: Record<Locale, string> = { en: "English", de: "Deutsch" };

export type Catalog = Readonly<Record<string, string>>;

/** Picks the first supported locale from a preference list such as `navigator.languages`. */
export function detectLocale(languages: readonly string[] | undefined): Locale {
  for (const language of languages ?? []) {
    const base = language.toLowerCase().split("-")[0];
    if ((LOCALES as readonly string[]).includes(base ?? "")) return base as Locale;
  }
  return "en";
}

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}

export type Translate = (key: string, params?: Params) => string;

export interface Translator {
  locale: Locale;
  t: Translate;
  /** "5 minutes ago", "vor 5 Minuten". */
  relativeTime(unixMs: number, now?: number): string;
  /** Date and time in the locale's format, for example "24.10.2026, 14:32". */
  dateTime(unixMs: number): string;
  date(unixMs: number): string;
  number(value: number): string;
  /** Locale-aware string comparison for sorting (Ä sorts with A in German). */
  compare(a: string, b: string): number;
}

/**
 * Creates a translator. `catalogs` maps each locale to its merged
 * namespaces; missing keys fall back to English, then to the key itself.
 */
export function createTranslator(locale: Locale, catalogs: Partial<Record<Locale, Catalog>>): Translator {
  const primary = catalogs[locale] ?? {};
  const fallback = catalogs.en ?? {};
  const collator = new Intl.Collator(locale, { sensitivity: "base", numeric: true });
  const relative = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  const dateTime = new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" });
  const date = new Intl.DateTimeFormat(locale, { dateStyle: "medium" });
  const numbers = new Intl.NumberFormat(locale);
  return {
    locale,
    t: (key, params = {}) => formatMessage(primary[key] ?? fallback[key] ?? key, params, locale),
    relativeTime(unixMs, now = Date.now()) {
      const seconds = Math.round((unixMs - now) / 1000);
      const abs = Math.abs(seconds);
      if (abs < 45) return relative.format(0, "second");
      if (abs < 45 * 60) return relative.format(Math.round(seconds / 60), "minute");
      if (abs < 22 * 3600) return relative.format(Math.round(seconds / 3600), "hour");
      if (abs < 26 * 86400) return relative.format(Math.round(seconds / 86400), "day");
      if (abs < 320 * 86400) return relative.format(Math.round(seconds / (30 * 86400)), "month");
      return relative.format(Math.round(seconds / (365 * 86400)), "year");
    },
    dateTime: (unixMs) => dateTime.format(unixMs),
    date: (unixMs) => date.format(unixMs),
    number: (value) => numbers.format(value),
    compare: (a, b) => collator.compare(a, b),
  };
}

/** Merges namespace catalogs, for example `mergeCatalogs(common, web)`. */
export function mergeCatalogs(...catalogs: Catalog[]): Catalog {
  return Object.assign({}, ...catalogs);
}
