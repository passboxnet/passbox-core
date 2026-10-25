/**
 * Have I Been Pwned through the user's own server (G6, G11): the Pwned
 * Passwords range proxy and email breach monitoring. See
 * docs/architecture/security-analysis.md.
 */

/** A breach a monitored address appeared in (Have I Been Pwned breach model). */
export interface EmailBreach {
  name: string;
  title: string;
  domain: string;
  /** `YYYY-MM-DD`. */
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  /** Kinds of exposed data, for example `Passwords`. */
  dataClasses: string[];
  /** When this server first saw the address in the breach (Unix ms). */
  firstSeenAt: number;
}

export interface MonitoredEmail {
  id: string;
  email: string;
  /** Confirmed with the mailed code; only confirmed addresses are checked. */
  verified: boolean;
  /** Last check (Unix ms, 0 = never). */
  checkedAt: number;
  checkError: string | null;
  createdAt: number;
  breaches: EmailBreach[];
}

export interface EmailMonitoring {
  /** The operator configured a Have I Been Pwned API key. */
  available: boolean;
  checkIntervalHours: number;
  emails: MonitoredEmail[];
}

export interface BreachApi {
  /**
   * The padded Pwned Passwords range for a 5-character SHA-1 prefix through
   * the server, or `null` when the server does not offer it (404).
   */
  range(prefix: string): Promise<string | null>;
  emails(): Promise<EmailMonitoring>;
  /** Adds an address; the server mails a confirmation code to it. */
  addEmail(email: string, locale?: string): Promise<MonitoredEmail>;
  verifyEmail(id: string, code: string): Promise<MonitoredEmail>;
  checkEmail(id: string): Promise<MonitoredEmail>;
  removeEmail(id: string): Promise<void>;
}

type Call = <T>(method: string, path: string, body?: unknown) => Promise<T>;

export function breachApi(call: Call, text: (path: string) => Promise<string | null>): BreachApi {
  const e = encodeURIComponent;
  return {
    range: (prefix) => text(`/api/v1/breach/range/${e(prefix.toUpperCase())}`),
    emails: () => call("GET", "/api/v1/breach/emails"),
    addEmail: (email, locale) => call("POST", "/api/v1/breach/emails", { email, locale }),
    verifyEmail: (id, code) => call("POST", `/api/v1/breach/emails/${e(id)}/verify`, { code }),
    checkEmail: (id) => call("POST", `/api/v1/breach/emails/${e(id)}/check`, {}),
    removeEmail: (id) => call("DELETE", `/api/v1/breach/emails/${e(id)}`),
  };
}
