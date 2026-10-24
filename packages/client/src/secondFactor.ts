import type { SecondFactor } from "@passbox/api-client";

/** Crockford Base32 as used by recovery codes (O, I and L are read as 0, 1, 1). */
const RECOVERY_CHARS = /^[0-9A-HJKMNP-TV-Z]{16}$/;

function compactRecoveryCode(input: string): string {
  return input.replace(/[\s-]/g, "").toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1");
}

/** Whether typed input is a recovery code (16 characters) rather than a 6-digit code. */
export function looksLikeRecoveryCode(input: string): boolean {
  return RECOVERY_CHARS.test(compactRecoveryCode(input));
}

/** The second factor for what was typed into a single code field. */
export function secondFactorFromInput(input: string): SecondFactor {
  const code = input.trim();
  return looksLikeRecoveryCode(code) ? { method: "recovery", code } : { method: "totp", code: code.replace(/\s/g, "") };
}
