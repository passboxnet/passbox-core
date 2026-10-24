import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { LOCALES } from "./index";

const root = join(import.meta.dirname, "..", "messages");
const load = (locale: string, file: string) =>
  JSON.parse(readFileSync(join(root, locale, file), "utf8")) as Record<string, string>;
const placeholders = (message: string) =>
  new Set([...message.matchAll(/\{\s*([A-Za-z0-9_]+)\s*[,}]/g)].map((m) => m[1]));

describe.each(readdirSync(join(root, "en")).filter((f) => f.endsWith(".json")))("%s", (file) => {
  const en = load("en", file);

  it.each(LOCALES.filter((l) => l !== "en"))("is complete in %s", (locale) => {
    const other = load(locale, file);
    expect(Object.keys(other).sort()).toEqual(Object.keys(en).sort());
    for (const [key, message] of Object.entries(en)) {
      expect(placeholders(other[key] ?? ""), `${locale}:${key}`).toEqual(placeholders(message));
    }
  });

  it("has only non-empty messages", () => {
    for (const locale of LOCALES) {
      for (const [key, message] of Object.entries(load(locale, file))) {
        expect(typeof message === "string" && message.trim() !== "", `${locale}:${key}`).toBe(true);
      }
    }
  });
});
