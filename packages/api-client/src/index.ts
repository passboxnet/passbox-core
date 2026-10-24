/** Argon2id cost parameters. Mirrors `passbox_core::kdf::KdfParams`. */
export interface KdfParams {
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export interface Health {
  status: "ok";
}

export interface ServerMeta {
  name: string;
  version: string;
  apiVersion: number;
  minKdfParams: KdfParams;
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
  | "password_changed";

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

export interface PassboxApi {
  health(): Promise<Health>;
  meta(): Promise<ServerMeta>;
  prelogin(email: string): Promise<PreloginResponse>;
  registerStart(req: { accountId: string; email: string; registrationRequest: string }): Promise<{
    registrationResponse: string;
  }>;
  registerFinish(req: RegisterFinishRequest): Promise<{ accountId: string }>;
  loginStart(req: { email: string; credentialRequest: string }): Promise<LoginStartResponse>;
  loginFinish(req: {
    loginId: string;
    credentialFinalization: string;
    deviceName?: string;
    clientKind?: ClientKind;
  }): Promise<LoginFinishResponse>;
  logout(): Promise<void>;
  account(): Promise<Account>;
  accountEvents(limit?: number): Promise<AccountEvent[]>;
  passwordChangeStart(req: { registrationRequest: string }): Promise<{ registrationResponse: string }>;
  passwordChangeFinish(req: {
    registrationUpload: string;
    kdfSalt: string;
    kdfParams: KdfParams;
    encryptedAccountKey: string;
  }): Promise<void>;
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
    logout: () => call("POST", "/api/v1/auth/logout", {}),
    account: () => call("GET", "/api/v1/account"),
    accountEvents: (limit = 50) => call("GET", `/api/v1/account/events?limit=${encodeURIComponent(limit)}`),
    passwordChangeStart: (req) => call("POST", "/api/v1/account/password/start", req),
    passwordChangeFinish: (req) => call("POST", "/api/v1/account/password/finish", req),
    sessions: () => call("GET", "/api/v1/sessions"),
    revokeSession: (id) => call("DELETE", `/api/v1/sessions/${encodeURIComponent(id)}`),
    revokeOtherSessions: () => call("POST", "/api/v1/sessions/revoke-others", {}),
    sync: (since) => call("GET", `/api/v1/sync?since=${encodeURIComponent(since)}`),
    createVault: (vault) => call("POST", "/api/v1/vaults", vault),
    updateVault: (id, req) => call("PUT", `/api/v1/vaults/${encodeURIComponent(id)}`, req),
    putItem: (id, req) => call("PUT", `/api/v1/items/${encodeURIComponent(id)}`, req),
    deleteItem: (id, revision) =>
      call("DELETE", `/api/v1/items/${encodeURIComponent(id)}?revision=${encodeURIComponent(revision)}`),
  };
}
