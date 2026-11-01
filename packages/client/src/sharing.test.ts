import { describe, expect, it } from "vitest";
import { isOrgLocked, type Org, orgLocks, type SharingView, withOrgLocks } from "./sharing";

const org = (id: string): Org => ({
  id,
  kind: "team",
  role: "owner",
  status: "confirmed",
  fingerprint: "",
  rootHash: "",
  verified: true,
  members: [],
  groups: [],
});

describe("organization locks", () => {
  it("reads the locks from a sync's sharing part", () => {
    const locks = orgLocks({
      orgs: [
        { id: "a", lock: { reason: "billing:payment_overdue", source: "billing" } },
        { id: "b", lock: null },
        { id: "c" },
        { id: "d", lock: { source: "billing" } },
      ],
    });
    expect([...locks]).toEqual([["a", { reason: "billing:payment_overdue", source: "billing" }]]);
    expect(orgLocks(undefined).size).toBe(0);
    expect(orgLocks({ orgs: "nonsense" }).size).toBe(0);
  });

  it("adds them to the verified view and clears them again", () => {
    const view: SharingView = { orgs: [org("a"), org("b")], vaults: [], warnings: [] };
    expect(withOrgLocks(view, new Map())).toBe(view);

    const locked = withOrgLocks(view, new Map([["a", { reason: "billing:no_plan", source: "billing" }]]));
    expect(locked.orgs.map((o) => isOrgLocked(o))).toEqual([true, false]);
    expect(locked.orgs[0]?.lock?.reason).toBe("billing:no_plan");

    const unlocked = withOrgLocks(locked, new Map());
    expect(unlocked.orgs.map((o) => isOrgLocked(o))).toEqual([false, false]);
  });
});
