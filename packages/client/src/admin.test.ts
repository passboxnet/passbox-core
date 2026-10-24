import { describe, expect, it } from "vitest";
import {
  AUDIT_CATEGORIES,
  auditCategory,
  auditDetails,
  canExportVault,
  canMoveBetween,
  clampAutoLock,
  NO_POLICY,
  policyTasks,
  securityAggregate,
} from "./admin";

const strict = {
  ...NO_POLICY,
  requireTwoFactor: true,
  twoFactorOrgs: ["o"],
  minPasswordScore: 3,
  maxAutoLockMinutes: 10,
  allowPersonalVault: false,
  personalVaultOrgs: ["o"],
  recoveryEnrollmentOrgs: ["o", "p"],
  exportBlockedOrgs: ["o"],
  externalSharingBlockedOrgs: ["o"],
};

describe("policy helpers", () => {
  it("clamps auto-lock to the limit", () => {
    expect(clampAutoLock(strict, 0)).toBe(10);
    expect(clampAutoLock(strict, 60)).toBe(10);
    expect(clampAutoLock(strict, 5)).toBe(5);
    expect(clampAutoLock(NO_POLICY, 0)).toBe(0);
  });

  it("blocks export and moves out of the organization", () => {
    expect(canExportVault(strict, { orgId: "o" })).toBe(false);
    expect(canExportVault(strict, { orgId: "p" })).toBe(true);
    expect(canExportVault(strict, {})).toBe(true);
    expect(canMoveBetween(strict, { orgId: "o" }, { orgId: "o" })).toBe(true);
    expect(canMoveBetween(strict, { orgId: "o" }, {})).toBe(false);
    expect(canMoveBetween(strict, { orgId: "o" }, { orgId: "p" })).toBe(false);
    expect(canMoveBetween(strict, {}, { orgId: "o" })).toBe(true);
  });

  it("lists what the account has to do", () => {
    expect(policyTasks(strict, { twoFactor: false, passwordScore: 2, enrolledOrgs: ["p"] })).toEqual([
      { kind: "two_factor", orgIds: ["o"] },
      { kind: "password_strength", orgIds: [] },
      { kind: "recovery_enrollment", orgIds: ["o"] },
    ]);
    // Unknown state never produces a task.
    expect(policyTasks(strict, { twoFactor: undefined, passwordScore: undefined, enrolledOrgs: ["o", "p"] })).toEqual(
      [],
    );
    expect(
      policyTasks({ ...NO_POLICY, hasUnknownRules: true }, { twoFactor: true, passwordScore: 4, enrolledOrgs: [] }),
    ).toEqual([{ kind: "update_app", orgIds: [] }]);
  });
});

describe("security aggregate", () => {
  it("reports counts only", () => {
    const aggregate = securityAggregate(
      {
        weak: ["a"],
        reused: [
          ["a", "b"],
          ["c", "d"],
        ],
        insecureUrls: ["e"],
        withoutTotp: ["a", "b"],
        secure: 1,
        score: 61.6,
        analyzed: 5,
      },
      true,
    );
    expect(aggregate).toEqual({ score: 62, total: 5, weak: 1, reused: 4, unsecured: 1, passwordMeetsPolicy: true });
    expect(JSON.stringify(aggregate)).not.toMatch(/"a"/);
  });
});

describe("audit helpers", () => {
  it("categorizes actions and parses details", () => {
    expect(auditCategory("item_copied")).toBe("usage");
    expect(auditCategory("member_signed_in")).toBe("signIn");
    expect(auditCategory("something_new")).toBe("other");
    expect(auditDetails({ details: '{"role":"admin"}' })).toEqual({ role: "admin" });
    expect(auditDetails({ details: "[1]" })).toEqual({});
    expect(auditDetails({ details: "nope" })).toEqual({});
    const all = Object.values(AUDIT_CATEGORIES).flat();
    expect(new Set(all).size).toBe(all.length);
  });
});
