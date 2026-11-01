/**
 * The hosted service (passbox.net): Business plans, billing and locked
 * organizations. A self-hosted server has none of this: its `meta` has no
 * `extensions.cloud`, and the `/api/v1/cloud/...` endpoints do not exist.
 */

export type BillingInterval = "month" | "year";

/** A Business plan. The price is per member and interval. */
export interface CloudPlan {
  code: "business-monthly" | "business-yearly";
  interval: BillingInterval;
  /** Price per member and interval, in cents. */
  amountCents: number;
  currency: "EUR";
  perUnit: true;
  unitLabel: "member";
}

/** What the hosted service adds; in `ServerMeta.extensions.cloud`. */
export interface CloudExtension {
  billing: true;
  plans: CloudPlan[];
}

/** Optional additions of a server, in `ServerMeta.extensions`. */
export interface ServerExtensions {
  cloud?: CloudExtension | undefined;
}

/**
 * Why an organization is read-only. The hosted service uses
 * `billing:payment_overdue` and `billing:no_plan`; other values may come.
 */
export type OrgLockReason = "billing:payment_overdue" | "billing:no_plan";

/**
 * A lock on an organization, as the server states it (not signed): members
 * can read, copy and fill, but nothing can be changed (403 `org_read_only`).
 */
export interface OrgLock {
  reason: OrgLockReason | string;
  /** Who set the lock, for example `billing`. */
  source: string;
}

/**
 * The state of an organization's subscription:
 * `setup` (no plan yet), `active`, `past_due` (a payment failed, still usable),
 * `suspended` (read-only until paid), `canceled`, or `exempt` (free of charge).
 */
export type CloudBillingStatus = "setup" | "active" | "past_due" | "suspended" | "canceled" | "exempt";

/** `GET /api/v1/cloud/orgs/{orgId}/billing`. */
export interface CloudBilling {
  status: CloudBillingStatus;
  planCode: string | null;
  interval: BillingInterval | null;
  /** Members who count now (confirmed, not guests). */
  seatsCounted: number;
  /** Members on the current invoice. */
  seatsBilled: number;
  /** Fewer members from the next period on, if members left; otherwise `null`. */
  pendingSeats: number | null;
  /** End of the current period (Unix ms). */
  currentPeriodEnd: number | null;
  readOnly: boolean;
}

/** Error codes of the hosted service (403). */
export type CloudErrorCode =
  /** The organization is locked; see `OrgLock`. */
  | "org_read_only"
  /** Adding members (not guests) or Business features needs an active subscription. */
  | "business_activation_required"
  /** A family has as many members as it may (`details.limit`). */
  | "family_limit_reached";

/**
 * Billing of an organization on the hosted service. Only the owner and
 * admins may call these, and only when `meta.extensions.cloud` is present.
 */
export interface CloudApi {
  cloudBilling(orgId: string): Promise<CloudBilling>;
  /** A checkout page of the billing service; open it with a top-level redirect. */
  cloudCheckout(orgId: string, interval: BillingInterval): Promise<{ url: string }>;
  /** The billing portal (payment method, invoices, cancellation); open it with a top-level redirect. */
  cloudPortal(orgId: string): Promise<{ url: string }>;
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

export function cloudApi(call: Call): CloudApi {
  const org = (id: string) => `/api/v1/cloud/orgs/${encodeURIComponent(id)}`;
  return {
    cloudBilling: (orgId) => call("GET", `${org(orgId)}/billing`),
    cloudCheckout: (orgId, interval) => call("POST", `${org(orgId)}/checkout`, { interval }),
    cloudPortal: (orgId) => call("POST", `${org(orgId)}/portal`, {}),
  };
}

/** The hosted service's plan for `interval`, if the server is the hosted service and offers it. */
export function cloudPlan(
  meta: { extensions?: ServerExtensions | undefined } | undefined,
  interval: BillingInterval,
): CloudPlan | undefined {
  return meta?.extensions?.cloud?.plans.find((plan) => plan.interval === interval);
}
