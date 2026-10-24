import { describe, expect, it } from "vitest";
import { formatMessage } from "./format";
import { createTranslator, detectLocale } from "./index";

describe("formatMessage", () => {
  it("inserts parameters and numbers", () => {
    expect(formatMessage("Hello {name}", { name: "Anna" }, "en")).toBe("Hello Anna");
    expect(formatMessage("{n} items", { n: 1234 }, "de")).toBe("1.234 items");
    expect(formatMessage("Missing {x}", {}, "en")).toBe("Missing {x}");
    expect(formatMessage("Literal '{'x'}'", {}, "en")).toBe("Literal {x}");
  });

  it("handles plurals with exact matches and nesting", () => {
    const message = "{count, plural, =0 {Keine Einträge} one {# Eintrag} other {# Einträge}}";
    expect(formatMessage(message, { count: 0 }, "de")).toBe("Keine Einträge");
    expect(formatMessage(message, { count: 1 }, "de")).toBe("1 Eintrag");
    expect(formatMessage(message, { count: 2500 }, "de")).toBe("2.500 Einträge");
    const nested = "{n, plural, one {{who} hat # Gerät} other {{who} hat # Geräte}}";
    expect(formatMessage(nested, { n: 3, who: "Anna" }, "de")).toBe("Anna hat 3 Geräte");
  });

  it("selects by value", () => {
    const message = "{kind, select, ios {iPhone} android {Android} other {Browser}}";
    expect(formatMessage(message, { kind: "ios" }, "en")).toBe("iPhone");
    expect(formatMessage(message, { kind: "web" }, "en")).toBe("Browser");
  });
});

describe("translator", () => {
  it("falls back to English and then the key", () => {
    const { t } = createTranslator("de", { en: { a: "A", b: "B" }, de: { a: "Ä" } });
    expect(t("a")).toBe("Ä");
    expect(t("b")).toBe("B");
    expect(t("c")).toBe("c");
  });

  it("formats dates and relative times per locale", () => {
    const de = createTranslator("de", {});
    const now = Date.UTC(2026, 9, 24, 12, 0);
    expect(de.relativeTime(now - 5 * 60_000, now)).toBe("vor 5 Minuten");
    expect(createTranslator("en", {}).relativeTime(now - 2 * 86_400_000, now)).toBe("2 days ago");
    expect(de.compare("Äpfel", "Birnen")).toBeLessThan(0);
  });

  it("detects the locale", () => {
    expect(detectLocale(["de-AT", "en"])).toBe("de");
    expect(detectLocale(["fr-FR", "en-GB"])).toBe("en");
    expect(detectLocale([])).toBe("en");
  });
});
