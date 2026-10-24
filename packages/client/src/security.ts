/**
 * Client-side security analysis: password strength and vault health
 * (Watchtower). Strength comes from the shared core (zxcvbn plus German
 * words), so web, extension, desktop and mobile agree. Everything runs on
 * decrypted data in memory; only `breachCount` contacts a server.
 */
import { FIELD, fieldValue } from "./items";

export type StrengthScore = 0 | 1 | 2 | 3 | 4;

export interface Strength {
  score: StrengthScore;
  label: "Very weak" | "Weak" | "Fair" | "Strong" | "Very strong";
  /** Estimated guesses to crack, as log2. */
  bits: number;
  /**
   * Code for a localized warning: `keyboard_row`, `keyboard_pattern`,
   * `repeated_chars`, `repeated_pattern`, `top_password`, `common_password`,
   * `similar_to_common`, `sequence`, `recent_year`, `single_word`, `date`,
   * `name` or `common_name`.
   */
  warning: string | null;
  /**
   * Codes for localized tips: `use_words`, `no_symbols_needed`, `add_words`,
   * `capitalization`, `all_uppercase`, `reversed`, `substitutions`,
   * `longer_keyboard_pattern`, `avoid_repeats`, `avoid_sequences`,
   * `avoid_recent_years`, `avoid_personal_years`, `avoid_personal_dates`.
   */
  suggestions: string[];
  /** Good enough for a master password (score ≥ 3 and at least 12 characters). */
  acceptableMasterPassword: boolean;
}

/** The part of `@passbox/core-wasm` the estimator needs. */
export interface StrengthCore {
  estimateStrength(password: string, userInputsJson: string): string;
}

const LABELS: Strength["label"][] = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

/**
 * Rates a password. `userInputs` are words an attacker would try first:
 * the account email, the user's name, the server host.
 */
export function estimateStrength(core: StrengthCore, password: string, userInputs: readonly string[] = []): Strength {
  const raw = JSON.parse(core.estimateStrength(password, JSON.stringify(userInputs))) as Omit<Strength, "label">;
  const score = Math.min(4, Math.max(0, raw.score)) as StrengthScore;
  return { ...raw, score, label: LABELS[score] as Strength["label"] };
}

export interface ItemLike {
  id: string;
  data: { category: string; fields: Array<{ id: string; type: string; value: string }>; trashedAt?: number };
}

export interface VaultHealth {
  /** Logins with a weak password (score ≤ 1). */
  weak: string[];
  /** Groups of logins sharing the same password. */
  reused: string[][];
  /** Logins whose website uses plain http. */
  insecureUrls: string[];
  /** Logins without a one-time password. */
  withoutTotp: string[];
  /** Analyzed logins without any problem. */
  secure: number;
  /** 0–100, higher is better. */
  score: number;
  /** Number of logins with a password that were analyzed. */
  analyzed: number;
}

/**
 * Analyzes logins for weak, reused and insecure entries. Trashed items are
 * skipped. `userInputs` are passed to the strength estimate.
 */
export function analyzeVault(
  core: StrengthCore,
  items: readonly ItemLike[],
  userInputs: readonly string[] = [],
): VaultHealth {
  const weak: string[] = [];
  const insecureUrls: string[] = [];
  const withoutTotp: string[] = [];
  const byPassword = new Map<string, string[]>();
  const passwords = new Set<string>();
  let analyzed = 0;

  for (const item of items) {
    if (item.data.category !== "login" || item.data.trashedAt !== undefined) continue;
    const data = item.data as Parameters<typeof fieldValue>[0];
    const password = fieldValue(data, FIELD.password);
    const url = fieldValue(data, FIELD.url);
    if (url && /^http:\/\//i.test(url.trim())) insecureUrls.push(item.id);
    if (!password) continue;
    analyzed++;
    passwords.add(item.id);
    if (estimateStrength(core, password, userInputs).score <= 1) weak.push(item.id);
    if (!fieldValue(data, FIELD.totp)) withoutTotp.push(item.id);
    byPassword.set(password, [...(byPassword.get(password) ?? []), item.id]);
  }

  const reused = [...byPassword.values()].filter((ids) => ids.length > 1);
  const problemIds = new Set([...weak, ...reused.flat(), ...insecureUrls]);
  const problems = problemIds.size;
  const secure = analyzed - [...problemIds].filter((id) => passwords.has(id)).length;
  const score = analyzed === 0 ? 100 : Math.round(100 * (1 - problems / Math.max(analyzed, problems)));
  return { weak, reused, insecureUrls, withoutTotp, secure, score, analyzed };
}

/**
 * Checks a password against Have I Been Pwned with k-anonymity: only the
 * first 5 hex characters of its SHA-1 hash leave the device. Returns how
 * often the password appears in known breaches (0 = not found).
 */
export async function breachCount(
  password: string,
  fetchImpl: typeof globalThis.fetch = globalThis.fetch.bind(globalThis),
): Promise<number> {
  if (!password) return 0;
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  const prefix = hex.slice(0, 5);
  const suffix = hex.slice(5);
  const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
    // Padding hides the number of real matches from observers.
    headers: { "Add-Padding": "true" },
  });
  if (!response.ok) throw new Error(`breach check failed with status ${response.status}`);
  for (const line of (await response.text()).split("\n")) {
    const [candidate, count] = line.trim().split(":");
    if (candidate === suffix) return Number(count) || 0;
  }
  return 0;
}
