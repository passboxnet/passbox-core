/**
 * Client-side security analysis: password strength and vault health
 * (Watchtower). Everything runs on decrypted data in memory; nothing is sent
 * anywhere.
 */
import { FIELD, fieldValue } from "./items";

export type StrengthScore = 0 | 1 | 2 | 3 | 4;

export interface Strength {
  score: StrengthScore;
  label: "Very weak" | "Weak" | "Fair" | "Strong" | "Very strong";
  /** Rough entropy estimate in bits after pattern penalties. */
  bits: number;
}

const LABELS: Strength["label"][] = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

/** A small list of the most common passwords; matches score as very weak. */
const COMMON = new Set([
  "123456",
  "123456789",
  "12345678",
  "password",
  "qwerty",
  "qwerty123",
  "1q2w3e4r",
  "111111",
  "123123",
  "abc123",
  "password1",
  "iloveyou",
  "admin",
  "welcome",
  "monkey",
  "dragon",
  "letmein",
  "football",
  "sunshine",
  "princess",
  "passwort",
  "hallo123",
  "schatz",
  "master",
  "secret",
]);

const SEQUENCES = [
  "abcdefghijklmnopqrstuvwxyz",
  "0123456789",
  "qwertyuiopasdfghjklzxcvbnm",
  "qwertzuiopasdfghjklyxcvbnm",
];

function charsetSize(password: string): number {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^a-zA-Z0-9]/.test(password)) size += 33;
  return size;
}

/** Number of characters that continue a run (aaa) or a sequence (abc, 321). */
function patternChars(password: string): number {
  const lower = password.toLowerCase();
  let count = 0;
  for (let i = 2; i < lower.length; i++) {
    const a = lower[i - 2] ?? "";
    const b = lower[i - 1] ?? "";
    const c = lower[i] ?? "";
    const run = a === b && b === c;
    const sequence = SEQUENCES.some((seq) => {
      const forward = seq.includes(a + b + c);
      const backward = seq.includes(c + b + a);
      return forward || backward;
    });
    if (run || sequence) count++;
  }
  return count;
}

/**
 * Estimates password strength from length, character variety and simple
 * patterns. It is a heuristic for user guidance, not a guarantee.
 */
export function estimateStrength(password: string): Strength {
  if (!password) return { score: 0, label: LABELS[0] as Strength["label"], bits: 0 };
  const normalized = password.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (COMMON.has(password.toLowerCase()) || COMMON.has(normalized)) {
    return { score: 0, label: "Very weak", bits: 0 };
  }
  const effectiveLength = Math.max(1, password.length - patternChars(password));
  let bits = effectiveLength * Math.log2(Math.max(charsetSize(password), 2));
  // Only letters and short: likely a dictionary word.
  if (/^[a-zA-Z]+$/.test(password) && password.length <= 10) bits = Math.min(bits, 25);
  // Word plus digits at the end ("summer2024") is a very common pattern.
  if (/^[a-zA-Z]+\d{1,4}[!.?]?$/.test(password)) bits *= 0.6;

  const score: StrengthScore = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { score, label: LABELS[score] as Strength["label"], bits: Math.round(bits) };
}

export interface ItemLike {
  id: string;
  data: { category: string; fields: Array<{ id: string; type: string; value: string }> };
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
  /** 0–100, higher is better. */
  score: number;
  /** Number of logins with a password that were analyzed. */
  analyzed: number;
}

/** Analyzes logins for weak, reused and insecure entries. */
export function analyzeVault(items: readonly ItemLike[]): VaultHealth {
  const weak: string[] = [];
  const insecureUrls: string[] = [];
  const withoutTotp: string[] = [];
  const byPassword = new Map<string, string[]>();
  let analyzed = 0;

  for (const item of items) {
    if (item.data.category !== "login") continue;
    const data = item.data as Parameters<typeof fieldValue>[0];
    const password = fieldValue(data, FIELD.password);
    const url = fieldValue(data, FIELD.url);
    if (url && /^http:\/\//i.test(url.trim())) insecureUrls.push(item.id);
    if (!password) continue;
    analyzed++;
    if (estimateStrength(password).score <= 1) weak.push(item.id);
    if (!fieldValue(data, FIELD.totp)) withoutTotp.push(item.id);
    byPassword.set(password, [...(byPassword.get(password) ?? []), item.id]);
  }

  const reused = [...byPassword.values()].filter((ids) => ids.length > 1);
  const problems = new Set([...weak, ...reused.flat(), ...insecureUrls]).size;
  const score = analyzed === 0 ? 100 : Math.round(100 * (1 - problems / Math.max(analyzed, problems)));
  return { weak, reused, insecureUrls, withoutTotp, score, analyzed };
}
