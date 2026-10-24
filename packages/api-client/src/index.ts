/** Argon2id cost parameters. Mirrors `passbox_core::kdf::KdfParams`. */
export interface KdfParams {
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export interface Health {
  status: "ok";
}

/** Who may create an account on a server. */
export type RegistrationMode = "open" | "invite_only" | "domains";

export type MailLocale = "en" | "de";

/**
 * Minimum strength of new master passwords. The server never sees the
 * password, so clients enforce it (together with their own minimum).
 */
export interface PasswordPolicy {
  /** Lowest strength score: 3 (strong) or 4 (very strong). */
  minScore: number;
  /** Lowest number of characters (at least 12). */
  minLength: number;
}

export interface ServerMeta {
  name: string;
  version: string;
  apiVersion: number;
  minKdfParams: KdfParams;
  /** Name the admins gave the server. Missing on servers before instance settings. */
  instanceName?: string;
  registration?: RegistrationMode;
  /** In `domains` mode: the email domains that may register. */
  allowedDomains?: string[];
  /** Where users get help, if the admins set it. */
  supportUrl?: string | null;
  defaultLocale?: MailLocale;
  passwordPolicy?: PasswordPolicy;
}

export interface PreloginResponse {
  accountId: string;
  kdfSalt: string;
  kdfParams: KdfParams;
}

export interface NewVault {
  id: string;
  encryptedKey: string;
  encryptedMeta: string;
}

export interface RegisterFinishRequest {
  accountId: string;
  email: string;
  registrationUpload: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  encryptedAccountKey: string;
  vault: NewVault;
  /** Token from an invitation link (`#/?invite=…`). */
  inviteToken?: string;
  /** Language for mails from the server. */
  locale?: MailLocale;
}

export interface LoginStartResponse {
  loginId: string;
  credentialResponse: string;
}

export interface LoginFinishResponse {
  token: string;
  accountId: string;
  sessionId: string;
  expiresAt: number;
  /**
   * Store it on the device and send it with the next `loginStart`; it
   * replaces the token sent there. It exempts the device from the per-email
   * login lockout and grants no access by itself.
   */
  deviceToken: string;
  /** Unused recovery codes left, after signing in with one. */
  recoveryCodesRemaining?: number;
}

export type TwoFactorMethod = "totp" | "webauthn" | "recovery";

/** A credential the browser may use, as in `PublicKeyCredentialDescriptor` (ID as Base64url). */
export interface WebAuthnCredentialDescriptor {
  type: "public-key";
  id: string;
}

/** `PublicKeyCredentialRequestOptions` with binary values as Base64url. */
export interface WebAuthnRequestOptionsJson {
  challenge: string;
  rpId: string;
  allowCredentials: WebAuthnCredentialDescriptor[];
  timeout: number;
  userVerification: "required" | "preferred" | "discouraged";
}

/** `PublicKeyCredentialCreationOptions` with binary values as Base64url. */
export interface WebAuthnCreationOptionsJson {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: "public-key"; alg: number }[];
  timeout: number;
  attestation: "none";
  excludeCredentials: WebAuthnCredentialDescriptor[];
  authenticatorSelection: {
    residentKey: "discouraged" | "preferred" | "required";
    userVerification: "required" | "preferred" | "discouraged";
  };
}

/**
 * Returned by `loginFinish` instead of a session when the account has
 * two-factor authentication on and this device is not remembered. Complete
 * it with `loginTwoFactor` within 5 minutes.
 */
export interface TwoFactorChallenge {
  twoFactorRequired: true;
  challengeToken: string;
  expiresAt: number;
  methods: TwoFactorMethod[];
  /** Present when the account has security keys for this origin. */
  webauthn?: WebAuthnRequestOptionsJson;
}

export type LoginFinishResult = LoginFinishResponse | TwoFactorChallenge;

export function isTwoFactorChallenge(result: LoginFinishResult): result is TwoFactorChallenge {
  return (result as TwoFactorChallenge).twoFactorRequired === true;
}

/** A WebAuthn assertion (`navigator.credentials.get`), binary values as Base64url. */
export interface WebAuthnAssertionJson {
  credentialId: string;
  clientDataJson: string;
  authenticatorData: string;
  signature: string;
}

/** A WebAuthn registration (`navigator.credentials.create`), binary values as Base64url. */
export interface WebAuthnAttestationJson {
  clientDataJson: string;
  attestationObject: string;
}

/** A second factor: a 6-digit code, a recovery code or a security key. */
export type SecondFactor =
  | { method: "totp"; code: string }
  | { method: "recovery"; code: string }
  | { method: "webauthn"; webauthn: WebAuthnAssertionJson };

export interface SecurityKeyInfo {
  id: string;
  name: string;
  createdAt: number;
  /** 0 if never used. */
  lastUsedAt: number;
}

export interface TwoFactorStatus {
  /** Whether sign-ins need a second factor. */
  enabled: boolean;
  totp: boolean;
  securityKeys: SecurityKeyInfo[];
  recoveryCodesRemaining: number;
}

export type ClientKind = "web" | "extension" | "desktop" | "ios" | "android" | "cli";

export interface SessionInfo {
  id: string;
  deviceName: string;
  clientKind: ClientKind | "";
  ip: string;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  /** True for the session making the request. */
  current: boolean;
}

export type AccountEventKind =
  | "account_created"
  | "login"
  | "login_failed"
  | "logout"
  | "session_revoked"
  | "other_sessions_revoked"
  | "password_changed"
  | "login_two_factor"
  | "two_factor_failed"
  | "two_factor_enabled"
  | "two_factor_disabled"
  | "two_factor_method_added"
  | "two_factor_method_removed"
  | "recovery_code_used"
  | "recovery_codes_regenerated";

export interface AccountEvent {
  id: string;
  kind: AccountEventKind | string;
  deviceName: string;
  clientKind: ClientKind | "";
  ip: string;
  createdAt: number;
}

export interface Account {
  accountId: string;
  email: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  encryptedAccountKey: string;
  /** Whether the account may use the instance administration. */
  instanceAdmin?: boolean;
}

/** Preferences the server needs: mail language and notifications. */
export interface AccountPreferences {
  /** `null`: the server's default language. */
  locale: MailLocale | null;
  /** Mail when a new device signs in. */
  notifyNewDevice: boolean;
}

export interface InstanceSettings {
  instanceName: string;
  registration: RegistrationMode;
  allowedDomains: string[];
  /** `""` for none. */
  supportUrl: string;
  defaultLocale: MailLocale;
  passwordPolicy: PasswordPolicy;
}

export interface MailStatus {
  /** False when no SMTP server is configured: mails are only written to the server log. */
  configured: boolean;
  transport: "smtps" | "starttls" | "smtp" | "log";
  host: string | null;
  from: string;
  publicUrl: string | null;
  pending: number;
  failed: number;
  lastSentAt: number | null;
  lastError: string | null;
}

export interface AdminSettings {
  settings: InstanceSettings;
  mail: MailStatus;
  /** Admins configured with `PASSBOX_ADMIN_EMAILS`. */
  envAdminEmails: string[];
}

export interface AdminUser {
  id: string;
  email: string;
  createdAt: number;
  lastActivityAt: number | null;
  status: "active" | "disabled";
  disabledAt: number | null;
  instanceAdmin: boolean;
  activeSessions: number;
  /** `null` while the server has no two-step sign-in. */
  twoFactorEnabled: boolean | null;
}

export interface AdminUsers {
  users: AdminUser[];
  total: number;
}

export type AdminEventAction =
  | "instance_admin_bootstrap"
  | "settings_updated"
  | "user_disabled"
  | "user_enabled"
  | "test_mail_sent"
  | "invite_created"
  | "invite_used"
  | "invite_revoked";

export interface AdminEvent {
  seq: number;
  id: string;
  actorId: string;
  actorEmail: string;
  action: AdminEventAction | string;
  target: string;
  details: Record<string, unknown> | null;
  ip: string;
  createdAt: number;
  prevHash: string;
  hash: string;
}

export interface AdminEvents {
  /** Newest first. */
  events: AdminEvent[];
  /** Result of checking the whole hash chain on the server. */
  chain: { valid: boolean; length: number; brokenAt: number | null };
}

export interface Invite {
  id: string;
  email: string;
  invitedBy: string;
  createdAt: number;
  expiresAt: number;
  usedAt: number | null;
  status: "pending" | "used" | "expired";
}

export interface InviteCreated extends Invite {
  /** The invitation link, also sent by mail; `null` if the server knows no public address. */
  link: string | null;
  mailConfigured: boolean;
}

/** Instance administration; every call needs an instance admin (else 403 `forbidden`). */
export interface AdminApi {
  adminSettings(): Promise<AdminSettings>;
  updateAdminSettings(settings: InstanceSettings): Promise<AdminSettings>;
  adminUsers(query?: { q?: string; limit?: number; offset?: number }): Promise<AdminUsers>;
  disableUser(id: string): Promise<void>;
  enableUser(id: string): Promise<void>;
  sendTestMail(to?: string): Promise<{ id: string; to: string; mailConfigured: boolean }>;
  adminEvents(query?: { limit?: number; before?: number }): Promise<AdminEvents>;
  adminInvites(): Promise<Invite[]>;
  createInvite(req: { email: string; locale?: MailLocale; linkBase?: string }): Promise<InviteCreated>;
  revokeInvite(id: string): Promise<void>;
}

export interface SyncVault {
  id: string;
  encryptedKey: string;
  encryptedMeta: string;
  revision: number;
  updatedAt: number;
}

export interface SyncItem {
  id: string;
  vaultId: string;
  revision: number;
  /** `null` for deleted items. */
  encryptedData: string | null;
  deleted: boolean;
  updatedAt: number;
}

export interface SyncResponse {
  cursor: number;
  vaults: SyncVault[];
  items: SyncItem[];
}

export interface WriteResponse {
  revision: number;
  seq: number;
}

export interface ErrorBody {
  error: string;
  message: string;
  details?: { currentRevision?: number } & Record<string, unknown>;
}

/** Thrown when the server answers with a non-2xx status. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    readonly body: ErrorBody | undefined,
  ) {
    super(body?.message ?? `Passbox API request to ${path} failed with status ${status}`);
    this.name = "ApiError";
  }

  /** Machine-readable error code, for example `conflict` or `invalid_credentials`. */
  get code(): string | undefined {
    return this.body?.error;
  }
}

export interface ClientOptions {
  /** Server origin, for example `https://passbox.example.com`. Defaults to the current origin. */
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  /** Returns the session token sent as bearer token, if any. */
  getToken?: () => string | undefined;
}

export interface PassboxApi extends AdminApi {
  health(): Promise<Health>;
  meta(): Promise<ServerMeta>;
  prelogin(email: string): Promise<PreloginResponse>;
  registerStart(req: { accountId: string; email: string; registrationRequest: string; inviteToken?: string }): Promise<{
    registrationResponse: string;
  }>;
  registerFinish(req: RegisterFinishRequest): Promise<{ accountId: string }>;
  loginStart(req: {
    email: string;
    credentialRequest: string;
    /** The device token from this device's last successful login. */
    deviceToken?: string;
  }): Promise<LoginStartResponse>;
  loginFinish(req: {
    loginId: string;
    credentialFinalization: string;
    deviceName?: string;
    clientKind?: ClientKind;
    /** `location.origin` of a web client, to be offered its security keys. */
    origin?: string;
  }): Promise<LoginFinishResult>;
  loginTwoFactor(
    req: SecondFactor & { challengeToken: string; rememberDevice?: boolean },
  ): Promise<LoginFinishResponse>;
  logout(): Promise<void>;
  account(): Promise<Account>;
  preferences(): Promise<AccountPreferences>;
  /** Changes the given preferences; `locale: ""` resets to the server default. */
  updatePreferences(changes: { locale?: MailLocale | ""; notifyNewDevice?: boolean }): Promise<AccountPreferences>;
  accountEvents(limit?: number): Promise<AccountEvent[]>;
  passwordChangeStart(req: { registrationRequest: string }): Promise<{ registrationResponse: string }>;
  passwordChangeFinish(req: {
    registrationUpload: string;
    kdfSalt: string;
    kdfParams: KdfParams;
    encryptedAccountKey: string;
  }): Promise<void>;
  twoFactorStatus(): Promise<TwoFactorStatus>;
  /** Needs a login in the last 10 minutes. */
  totpStart(): Promise<{ secret: string; uri: string }>;
  totpConfirm(code: string): Promise<{ recoveryCodes?: string[] }>;
  totpRemove(): Promise<void>;
  webauthnRegisterStart(origin: string): Promise<{ registrationId: string; publicKey: WebAuthnCreationOptionsJson }>;
  webauthnRegisterFinish(req: {
    registrationId: string;
    name: string;
    credential: WebAuthnAttestationJson;
  }): Promise<{ id: string; recoveryCodes?: string[] }>;
  webauthnRemove(id: string): Promise<void>;
  regenerateRecoveryCodes(): Promise<{ recoveryCodes: string[] }>;
  /** A challenge for checking a second factor while signed in (needed for security keys). */
  twoFactorChallenge(origin?: string): Promise<Omit<TwoFactorChallenge, "twoFactorRequired">>;
  disableTwoFactor(req: SecondFactor & { challengeToken?: string }): Promise<void>;
  sessions(): Promise<SessionInfo[]>;
  revokeSession(id: string): Promise<void>;
  revokeOtherSessions(): Promise<void>;
  sync(since: number): Promise<SyncResponse>;
  createVault(vault: NewVault): Promise<WriteResponse>;
  updateVault(id: string, req: { revision: number; encryptedMeta: string }): Promise<WriteResponse>;
  putItem(id: string, req: { vaultId: string; revision: number; encryptedData: string }): Promise<WriteResponse>;
  deleteItem(id: string, revision: number): Promise<WriteResponse>;
}

export function createClient(options: ClientOptions = {}): PassboxApi {
  const baseUrl = (options.baseUrl ?? "").replace(/\/+$/, "");
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json" };
    const token = options.getToken?.();
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const init: RequestInit = { method, headers };
    if (body !== undefined) init.body = JSON.stringify(body);

    const response = await doFetch(`${baseUrl}${path}`, init);
    if (!response.ok) {
      let errorBody: ErrorBody | undefined;
      try {
        errorBody = (await response.json()) as ErrorBody;
      } catch {
        errorBody = undefined;
      }
      throw new ApiError(response.status, path, errorBody);
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  return {
    health: () => call("GET", "/health"),
    meta: () => call("GET", "/api/v1/meta"),
    prelogin: (email) => call("POST", "/api/v1/auth/prelogin", { email }),
    registerStart: (req) => call("POST", "/api/v1/auth/register/start", req),
    registerFinish: (req) => call("POST", "/api/v1/auth/register/finish", req),
    loginStart: (req) => call("POST", "/api/v1/auth/login/start", req),
    loginFinish: (req) => call("POST", "/api/v1/auth/login/finish", req),
    loginTwoFactor: (req) => call("POST", "/api/v1/auth/login/two-factor", req),
    logout: () => call("POST", "/api/v1/auth/logout", {}),
    account: () => call("GET", "/api/v1/account"),
    preferences: () => call("GET", "/api/v1/account/preferences"),
    updatePreferences: (changes) => call("PUT", "/api/v1/account/preferences", changes),
    accountEvents: (limit = 50) => call("GET", `/api/v1/account/events?limit=${encodeURIComponent(limit)}`),
    passwordChangeStart: (req) => call("POST", "/api/v1/account/password/start", req),
    passwordChangeFinish: (req) => call("POST", "/api/v1/account/password/finish", req),
    twoFactorStatus: () => call("GET", "/api/v1/account/two-factor"),
    totpStart: () => call("POST", "/api/v1/account/two-factor/totp/start", {}),
    totpConfirm: (code) => call("POST", "/api/v1/account/two-factor/totp/confirm", { code }),
    totpRemove: () => call("DELETE", "/api/v1/account/two-factor/totp"),
    webauthnRegisterStart: (origin) => call("POST", "/api/v1/account/two-factor/webauthn/register/start", { origin }),
    webauthnRegisterFinish: (req) => call("POST", "/api/v1/account/two-factor/webauthn/register/finish", req),
    webauthnRemove: (id) => call("DELETE", `/api/v1/account/two-factor/webauthn/${encodeURIComponent(id)}`),
    regenerateRecoveryCodes: () => call("POST", "/api/v1/account/two-factor/recovery-codes", {}),
    twoFactorChallenge: (origin) => call("POST", "/api/v1/account/two-factor/challenge", origin ? { origin } : {}),
    disableTwoFactor: (req) => call("POST", "/api/v1/account/two-factor/disable", req),
    sessions: () => call("GET", "/api/v1/sessions"),
    revokeSession: (id) => call("DELETE", `/api/v1/sessions/${encodeURIComponent(id)}`),
    revokeOtherSessions: () => call("POST", "/api/v1/sessions/revoke-others", {}),
    sync: (since) => call("GET", `/api/v1/sync?since=${encodeURIComponent(since)}`),
    createVault: (vault) => call("POST", "/api/v1/vaults", vault),
    updateVault: (id, req) => call("PUT", `/api/v1/vaults/${encodeURIComponent(id)}`, req),
    putItem: (id, req) => call("PUT", `/api/v1/items/${encodeURIComponent(id)}`, req),
    deleteItem: (id, revision) =>
      call("DELETE", `/api/v1/items/${encodeURIComponent(id)}?revision=${encodeURIComponent(revision)}`),
    adminSettings: () => call("GET", "/api/v1/admin/settings"),
    updateAdminSettings: (settings) => call("PUT", "/api/v1/admin/settings", settings),
    adminUsers: (query = {}) => call("GET", `/api/v1/admin/users${queryString(query)}`),
    disableUser: (id) => call("POST", `/api/v1/admin/users/${encodeURIComponent(id)}/disable`, {}),
    enableUser: (id) => call("POST", `/api/v1/admin/users/${encodeURIComponent(id)}/enable`, {}),
    sendTestMail: (to) => call("POST", "/api/v1/admin/mail/test", to ? { to } : {}),
    adminEvents: (query = {}) => call("GET", `/api/v1/admin/events${queryString(query)}`),
    adminInvites: () => call("GET", "/api/v1/admin/invites"),
    createInvite: (req) => call("POST", "/api/v1/admin/invites", req),
    revokeInvite: (id) => call("DELETE", `/api/v1/admin/invites/${encodeURIComponent(id)}`),
  };
}

/** `?a=1&b=x` from the defined values, or `""`. */
function queryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}
