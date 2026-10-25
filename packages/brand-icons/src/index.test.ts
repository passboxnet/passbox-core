import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import manifest from "../manifest.json";
import services from "../services.json";
import { brandIcon, brandIconInfo, brandIcons } from "./index";

describe("brandIcon", () => {
  it("finds icons by ID, host name, subdomain and URL", () => {
    expect(brandIconInfo("okta")?.name).toBe("Okta");
    expect(brandIconInfo("okta.com")?.id).toBe("okta");
    expect(brandIconInfo("acme.okta.com")?.id).toBe("okta");
    expect(brandIconInfo("https://www.okta.com/login")?.id).toBe("okta");
    expect(brandIconInfo("OKTA.COM.")?.id).toBe("okta");
    expect(brandIconInfo("api.mistral.ai")?.id).toBe("mistral");
    expect(brandIconInfo("zitadel.cloud")?.id).toBe("zitadel");
    expect(brandIconInfo("relay.firefox.com")?.id).toBe("firefox-relay");
    expect(brandIconInfo("firefox.com")?.id).toBe("firefox");
    expect(brandIcon("1password")).toMatch(/1password\.png$/);
  });

  it("returns undefined for unknown services", () => {
    expect(brandIcon("example.com")).toBeUndefined();
    expect(brandIcon("com")).toBeUndefined();
    expect(brandIcon("")).toBeUndefined();
    expect(brandIcon(undefined)).toBeUndefined();
    expect(brandIcon("not a url://")).toBeUndefined();
  });

  it("has every service of the brief with a file and a source", () => {
    const required = [
      // Import sources, alias and identity providers, SIEMs, platforms, agents, AI providers.
      ["1password", "bitwarden", "lastpass", "dashlane", "keeper", "protonpass", "keepass", "keepassxc"],
      ["chrome", "google-password-manager", "firefox", "edge", "safari", "apple-passwords", "passbolt"],
      ["nordpass", "enpass", "roboform", "simplelogin", "addy", "fastmail", "duckduckgo", "firefox-relay"],
      ["entra", "google", "okta", "keycloak", "authentik", "zitadel"],
      ["splunk", "sentinel", "elastic", "graylog", "wazuh"],
      ["brave", "windows", "macos", "linux", "ios", "app-store", "android", "google-play"],
      ["claude", "anthropic", "cursor", "vscode", "openai", "github", "hibp", "2fa-directory"],
      ["langdock", "mistral", "ionos", "stackit", "scaleway", "ollama"],
    ].flat();
    const ids = brandIcons().map((icon) => icon.id);
    for (const id of required) expect(ids, id).toContain(id);
    for (const entry of manifest.icons) {
      expect(entry.source).toMatch(/^https:\/\//);
      expect(entry.fetched).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      const file = fileURLToPath(new URL(`../icons/${entry.id}.png`, import.meta.url));
      expect(existsSync(file), file).toBe(true);
      // A PNG of 64×64 pixels.
      const png = readFileSync(file);
      expect(png.subarray(1, 4).toString("ascii")).toBe("PNG");
      expect(png.readUInt32BE(16)).toBe(64);
      expect(png.readUInt32BE(20)).toBe(64);
    }
  });

  it("keeps the manifest in line with the service list", () => {
    const listed = new Set(services.services.map((service) => service.id));
    for (const entry of manifest.icons) expect(listed.has(entry.id), entry.id).toBe(true);
  });
});
