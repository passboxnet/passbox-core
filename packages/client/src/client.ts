import {
  type AccountEvent,
  ApiError,
  type ClientKind,
  type KdfParams,
  type PassboxApi,
  type SessionInfo,
  type SyncResponse,
} from "@passbox/api-client";
import type * as Core from "@passbox/core-wasm";
import {
  FIELD,
  fieldValue,
  type ItemData,
  PASSWORD_HISTORY_LEN,
  parseItemData,
  parseVaultMeta,
  TRASH_RETENTION_MS,
} from "./items";
import { analyzeVault, estimateStrength, type Strength, type VaultHealth } from "./security";
import type { KeyValueStorage } from "./storage";

type CoreModule = typeof Core;

/**
 * What this device remembers about the signed-in account. Like 1Password, the
 * Secret Key is kept on trusted devices so users only type it once per device.
 * Nothing here decrypts data without the master password.
 */
export interface DeviceAccount {
  email: string;
  accountId: string;
  secretKey: string;
  kdfSalt: string;
  kdfParams: KdfParams;
}

export interface Vault {
  id: string;
  name: string;
  revision: number;
}

export interface Item {
  id: string;
  vaultId: string;
  revision: number;
  updatedAt: number;
  data: ItemData;
}

/**
 * What a short-lived process needs to resume an unlocked session without the
 * master password: the keyring encrypted under a one-time session key, plus
 * the server session token. Keep it in memory-only storage only (for example
 * `chrome.storage.session`) and discard it on lock.
 */
export interface SessionState {
  accountId: string;
  sessionKey: string;
  blob: string;
  token: string;
}

export type ClientStatus = "signed-out" | "locked" | "unlocked";

/** One item for `PassboxClient.importItems`. */
export interface ImportEntry {
  data: ItemData;
  /** Update this existing item instead of creating a new one. */
  updateId?: string;
}

export interface ImportItemsOptions {
  /** Called after each item with the number processed so far. */
  onProgress?: (done: number, total: number) => void;
  signal?: AbortSignal;
  /** Requests in flight at once (default 6). */
  concurrency?: number;
  /** Items between snapshot updates (default 200). */
  batchSize?: number;
}

export interface ImportItemsResult {
  created: number;
  updated: number;
  failed: { title: string; error: string }[];
}

export interface ClientSnapshot {
  status: ClientStatus;
  email: string | undefined;
  vaults: Vault[];
  /** Items sorted by title, without those in the trash. */
  items: Item[];
  /** Items in the trash, most recently trashed first. */
  trash: Item[];
  /** Items or vaults that could not be decrypted (tampered or unsupported). */
  errors: string[];
}

/** Thrown when the email, master password or Secret Key is wrong. */
export class InvalidCredentialsError extends Error {
  constructor() {
    super("The email, master password or Secret Key is incorrect.");
    this.name = "InvalidCredentialsError";
  }
}

/** Thrown when an item was changed on another device in the meantime. */
export class ConflictError extends Error {
  constructor() {
    super("This item was changed on another device. The latest version has been loaded.");
    this.name = "ConflictError";
  }
}

const ACCOUNT_KEY = "passbox.account";
/**
 * The server's device token for this device. It exempts the device from the
 * per-email login lockout (so failed logins by someone else cannot block
 * unlocking) and grants no access by itself. Every login replaces it.
 */
const DEVICE_TOKEN_KEY = "passbox.deviceToken";

function isInvalidCredentials(error: unknown): boolean {
  return (
    (error instanceof Error && error.name === "InvalidCredentialsError") ||
    (error instanceof ApiError && error.code === "invalid_credentials")
  );
}

export interface PassboxClientOptions {
  core: CoreModule;
  /** API client whose `getToken` returns `client.token`. Use `createApi`. */
  api: PassboxApi;
  storage: KeyValueStorage;
  /** Identifies this device in the user's device list. */
  device?: { name: string; kind: ClientKind };
}

/**
 * Account, keys and vault data of one signed-in user.
 *
 * Unlocking always performs a full OPAQUE login, so the session token only
 * lives in memory and never needs to be stored.
 */
export class PassboxClient {
  private readonly core: CoreModule;
  private readonly api: PassboxApi;
  private readonly storage: KeyValueStorage;
  private readonly device: { name: string; kind: ClientKind } | undefined;
  private keyring: Core.Keyring | undefined;
  private cursor = 0;
  private vaults = new Map<string, Vault>();
  private items = new Map<string, Item>();
  private errors = new Map<string, string>();
  private listeners = new Set<() => void>();
  private snapshot: ClientSnapshot;
  /** Session token of the current unlock. */
  token: string | undefined;

  constructor(options: PassboxClientOptions) {
    this.core = options.core;
    this.api = options.api;
    this.storage = options.storage;
    this.device = options.device;
    this.snapshot = this.buildSnapshot();
  }

  // --- State -------------------------------------------------------------------

  get deviceAccount(): DeviceAccount | undefined {
    const raw = this.storage.getItem(ACCOUNT_KEY);
    return raw ? (JSON.parse(raw) as DeviceAccount) : undefined;
  }

  getSnapshot = (): ClientSnapshot => this.snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private emit() {
    this.snapshot = this.buildSnapshot();
    for (const listener of this.listeners) listener();
  }

  private buildSnapshot(): ClientSnapshot {
    const account = this.deviceAccount;
    return {
      status: this.keyring ? "unlocked" : account ? "locked" : "signed-out",
      email: account?.email,
      vaults: [...this.vaults.values()].sort((a, b) => a.name.localeCompare(b.name)),
      items: [...this.items.values()]
        .filter((item) => item.data.trashedAt === undefined)
        .sort((a, b) => a.data.title.localeCompare(b.data.title)),
      trash: [...this.items.values()]
        .filter((item) => item.data.trashedAt !== undefined)
        .sort((a, b) => (b.data.trashedAt ?? 0) - (a.data.trashedAt ?? 0)),
      errors: [...this.errors.values()],
    };
  }

  // --- Account -----------------------------------------------------------------

  /**
   * Creates an account with a personal vault and unlocks it. Returns the new
   * Secret Key, which the user must store in their Emergency Kit.
   */
  async signUp(email: string, password: string): Promise<{ secretKey: string; accountId: string }> {
    const { core } = this;
    const account: DeviceAccount = {
      email: email.trim().toLowerCase(),
      accountId: core.newId(),
      secretKey: core.generateSecretKey(),
      kdfSalt: core.generateKdfSalt(),
      kdfParams: JSON.parse(core.defaultKdfParams()) as KdfParams,
    };
    const keys = this.deriveKeys(account, password);
    try {
      const registration = core.RegistrationFlow.start(keys);
      const { registrationResponse } = await this.api.registerStart({
        accountId: account.accountId,
        email: account.email,
        registrationRequest: registration.request,
      });
      const registrationUpload = registration.finish(registrationResponse);
      registration.free();

      const keyring = core.Keyring.create(keys, account.accountId);
      const vault = JSON.parse(keyring.createVault(JSON.stringify({ name: "Private" }))) as {
        id: string;
        encryptedKey: string;
        encryptedMeta: string;
      };
      await this.api.registerFinish({
        accountId: account.accountId,
        email: account.email,
        registrationUpload,
        kdfSalt: account.kdfSalt,
        kdfParams: account.kdfParams,
        encryptedAccountKey: keyring.encryptedAccountKey ?? "",
        vault,
      });
      keyring.free();

      await this.login(account, keys);
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
      await this.sync();
      return { secretKey: account.secretKey, accountId: account.accountId };
    } finally {
      keys.free();
    }
  }

  /** Signs in on a new device with email, master password and Secret Key. */
  async signIn(email: string, password: string, secretKey: string): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    let normalizedKey: string;
    try {
      normalizedKey = this.core.normalizeSecretKey(secretKey);
    } catch {
      throw new InvalidCredentialsError();
    }
    const prelogin = await this.api.prelogin(normalizedEmail);
    const account: DeviceAccount = {
      email: normalizedEmail,
      accountId: prelogin.accountId,
      secretKey: normalizedKey,
      kdfSalt: prelogin.kdfSalt,
      kdfParams: prelogin.kdfParams,
    };
    const keys = this.deriveKeys(account, password);
    try {
      await this.login(account, keys);
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
    } finally {
      keys.free();
    }
    await this.sync();
  }

  /** Unlocks the account remembered on this device. */
  async unlock(password: string): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    const keys = this.deriveKeys(account, password);
    try {
      await this.login(account, keys);
    } finally {
      keys.free();
    }
    await this.sync();
  }

  // --- Account security ----------------------------------------------------------

  /** Devices signed in to this account. */
  async sessions(): Promise<SessionInfo[]> {
    this.requireKeyring();
    return this.api.sessions();
  }

  /** Signs out one device. */
  async revokeSession(id: string): Promise<void> {
    this.requireKeyring();
    await this.api.revokeSession(id);
  }

  /** Signs out every device except this one. */
  async revokeOtherSessions(): Promise<void> {
    this.requireKeyring();
    await this.api.revokeOtherSessions();
  }

  /** Recent sign-ins, failed attempts and other security events. */
  async activity(limit = 50): Promise<AccountEvent[]> {
    this.requireKeyring();
    return this.api.accountEvents(limit);
  }

  /**
   * Changes the master password. The current password is verified with a
   * fresh login (the server only accepts the change from a recent login).
   * Vaults and items stay as they are; every other device is signed out.
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    const currentKeys = this.deriveKeys(account, currentPassword);
    try {
      await this.login(account, currentKeys);
    } finally {
      currentKeys.free();
    }
    const keyring = this.requireKeyring();
    const next: DeviceAccount = { ...account, kdfSalt: this.core.generateKdfSalt() };
    const newKeys = this.deriveKeys(next, newPassword);
    try {
      const registration = this.core.RegistrationFlow.start(newKeys);
      const { registrationResponse } = await this.api.passwordChangeStart({
        registrationRequest: registration.request,
      });
      const registrationUpload = registration.finish(registrationResponse);
      registration.free();
      await this.api.passwordChangeFinish({
        registrationUpload,
        kdfSalt: next.kdfSalt,
        kdfParams: next.kdfParams,
        encryptedAccountKey: keyring.wrapAccountKey(newKeys),
      });
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(next));
    } finally {
      newKeys.free();
    }
  }

  /**
   * Checks the master password before a sensitive action (such as an
   * export) without signing in again: the derived key must decrypt the
   * account key. Returns `false` for a wrong password.
   */
  async verifyMasterPassword(password: string): Promise<boolean> {
    this.requireKeyring();
    const account = this.deviceAccount;
    if (!account) return false;
    const remote = await this.api.account();
    let keys: Core.MasterKeys | undefined;
    try {
      keys = this.deriveKeys(account, password);
      this.core.Keyring.unlock(keys, remote.accountId, remote.encryptedAccountKey).free();
      return true;
    } catch (error) {
      if (error instanceof InvalidCredentialsError || isInvalidCredentials(error)) return false;
      throw error;
    } finally {
      keys?.free();
    }
  }

  /** Exports the unlocked session, or `undefined` when locked. */
  exportSession(): SessionState | undefined {
    const account = this.deviceAccount;
    if (!this.keyring || !this.token || !account) return undefined;
    const { sessionKey, blob } = JSON.parse(this.keyring.exportSession()) as { sessionKey: string; blob: string };
    return { accountId: account.accountId, sessionKey, blob, token: this.token };
  }

  /**
   * Resumes a session exported with `exportSession` and syncs. Throws (and
   * stays locked) if the state does not belong to this device's account or
   * the server session has ended.
   */
  async restoreSession(state: SessionState): Promise<void> {
    const account = this.deviceAccount;
    if (!account || account.accountId !== state.accountId) throw new Error("session belongs to another account");
    this.clearSession();
    this.keyring = this.core.Keyring.importSession(state.sessionKey, state.accountId, state.blob);
    this.token = state.token;
    try {
      await this.sync();
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        this.clearSession();
        this.emit();
      }
      throw error;
    }
  }

  /** Forgets all decrypted data and keys. The account stays on this device. */
  lock(): void {
    // The API client reads the token when the request starts, so start the
    // logout before clearing it. Best effort: the session expires anyway.
    const logout = this.token ? this.api.logout() : undefined;
    this.clearSession();
    void logout?.catch(() => undefined);
    this.emit();
  }

  /** Locks and removes the account from this device. */
  signOut(): void {
    this.lock();
    this.storage.removeItem(ACCOUNT_KEY);
    this.storage.removeItem(DEVICE_TOKEN_KEY);
    this.emit();
  }

  private clearSession() {
    this.keyring?.free();
    this.keyring = undefined;
    this.token = undefined;
    this.cursor = 0;
    this.vaults.clear();
    this.items.clear();
    this.errors.clear();
  }

  private deriveKeys(account: DeviceAccount, password: string): Core.MasterKeys {
    try {
      return this.core.MasterKeys.derive(
        password,
        account.secretKey,
        account.accountId,
        account.kdfSalt,
        JSON.stringify(account.kdfParams),
      );
    } catch (error) {
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    }
  }

  /** Runs the OPAQUE login and unlocks the keyring. */
  private async login(account: DeviceAccount, keys: Core.MasterKeys): Promise<void> {
    const flow = this.core.LoginFlow.start(keys);
    try {
      // The server ignores a device token that belongs to another account.
      const deviceToken = this.storage.getItem(DEVICE_TOKEN_KEY) ?? undefined;
      const start = await this.api.loginStart({
        email: account.email,
        credentialRequest: flow.request,
        ...(deviceToken ? { deviceToken } : {}),
      });
      const credentialFinalization = flow.finish(start.credentialResponse);
      const finish = await this.api.loginFinish({
        loginId: start.loginId,
        credentialFinalization,
        ...(this.device ? { deviceName: this.device.name, clientKind: this.device.kind } : {}),
      });
      const { token } = finish;
      if (finish.deviceToken) this.storage.setItem(DEVICE_TOKEN_KEY, finish.deviceToken);
      this.clearSession();
      this.token = token;
      const remote = await this.api.account();
      this.keyring = this.core.Keyring.unlock(keys, remote.accountId, remote.encryptedAccountKey);
    } catch (error) {
      this.clearSession();
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    } finally {
      flow.free();
    }
  }

  // --- Sync --------------------------------------------------------------------

  /** Fetches and decrypts everything that changed since the last sync. */
  async sync(): Promise<void> {
    const keyring = this.requireKeyring();
    const delta = await this.api.sync(this.cursor);
    if (this.keyring !== keyring) return; // locked meanwhile
    this.apply(keyring, delta);
    this.emit();
  }

  private apply(keyring: Core.Keyring, delta: SyncResponse) {
    for (const vault of delta.vaults) {
      try {
        if (!keyring.hasVault(vault.id)) keyring.addVault(vault.id, vault.encryptedKey);
        const meta = parseVaultMeta(keyring.decryptVaultMeta(vault.id, vault.encryptedMeta));
        this.vaults.set(vault.id, { id: vault.id, name: meta.name, revision: vault.revision });
        this.errors.delete(vault.id);
      } catch (error) {
        this.errors.set(vault.id, `Vault ${vault.id} could not be decrypted: ${String(error)}`);
      }
    }
    for (const item of delta.items) {
      if (item.deleted || item.encryptedData === null) {
        this.items.delete(item.id);
        this.errors.delete(item.id);
        continue;
      }
      try {
        const json = keyring.decryptItem(item.vaultId, item.id, item.revision, item.encryptedData);
        this.items.set(item.id, {
          id: item.id,
          vaultId: item.vaultId,
          revision: item.revision,
          updatedAt: item.updatedAt,
          data: parseItemData(json),
        });
        this.errors.delete(item.id);
      } catch (error) {
        this.items.delete(item.id);
        this.errors.set(item.id, `Item ${item.id} could not be decrypted: ${String(error)}`);
      }
    }
    this.cursor = Math.max(this.cursor, delta.cursor);
  }

  private requireKeyring(): Core.Keyring {
    if (!this.keyring) throw new Error("vault is locked");
    return this.keyring;
  }

  // --- Editing -----------------------------------------------------------------

  /** Creates a new vault and returns its ID. */
  async createVault(name: string): Promise<string> {
    const keyring = this.requireKeyring();
    const vault = JSON.parse(keyring.createVault(JSON.stringify({ name }))) as {
      id: string;
      encryptedKey: string;
      encryptedMeta: string;
    };
    await this.api.createVault(vault);
    await this.sync();
    return vault.id;
  }

  /** Renames a vault. */
  async renameVault(id: string, name: string): Promise<void> {
    const keyring = this.requireKeyring();
    const vault = this.vaults.get(id);
    if (!vault) throw new Error("unknown vault");
    const revision = vault.revision + 1;
    try {
      await this.api.updateVault(id, {
        revision,
        encryptedMeta: keyring.encryptVaultMeta(id, JSON.stringify({ name })),
      });
    } catch (error) {
      await this.handleWriteError(error);
    }
    await this.sync();
  }

  /** Creates an item and returns its ID. */
  async createItem(vaultId: string, data: ItemData): Promise<string> {
    const id = this.core.newId();
    await this.writeItem(vaultId, id, 1, data);
    return id;
  }

  /**
   * Saves a new version of an existing item. A replaced password is added
   * to the password history; history and trash state always come from the
   * stored version, not from `data`.
   */
  async updateItem(id: string, data: ItemData): Promise<void> {
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    await this.writeItem(item.vaultId, id, item.revision + 1, this.nextVersion(item, data));
  }

  private nextVersion(item: Item, data: ItemData): ItemData {
    const { passwordHistory: _ignored, trashedAt: _trashed, ...rest } = data;
    const next: ItemData = rest;
    const oldPassword = fieldValue(item.data, FIELD.password);
    let history = item.data.passwordHistory ?? [];
    if (oldPassword !== undefined && fieldValue(data, FIELD.password) !== oldPassword) {
      history = [{ value: oldPassword, replacedAt: Date.now() }, ...history].slice(0, PASSWORD_HISTORY_LEN);
    }
    if (history.length > 0) next.passwordHistory = history;
    if (item.data.trashedAt !== undefined) next.trashedAt = item.data.trashedAt;
    return next;
  }

  /**
   * Creates many items (and, with `updateId`, updates existing ones as
   * `updateItem` does) with several requests in flight and a single sync at
   * the end, for imports of tens of thousands of items. Progress is reported
   * after each item; the snapshot is refreshed every `batchSize` items.
   * Items that fail are reported and do not stop the import. Stops early
   * when `signal` is aborted.
   */
  async importItems(
    vaultId: string,
    entries: readonly ImportEntry[],
    options: ImportItemsOptions = {},
  ): Promise<ImportItemsResult> {
    const keyring = this.requireKeyring();
    if (!this.vaults.has(vaultId)) throw new Error("unknown vault");
    const maxConcurrency = Math.max(1, options.concurrency ?? 6);
    const batchSize = Math.max(1, options.batchSize ?? 200);
    const result: ImportItemsResult = { created: 0, updated: 0, failed: [] };
    const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
    // Fewer requests run in parallel while the server is struggling (for
    // example "database is locked" on SQLite), more again once it recovers.
    let limit = maxConcurrency;
    let streak = 0;
    let next = 0;
    let done = 0;
    let sinceEmit = 0;
    const active = () => next < entries.length && !options.signal?.aborted && this.keyring === keyring;

    /** One write, retried on server errors and dropped connections. */
    const save = async (entry: ImportEntry) => {
      const existing = entry.updateId ? this.items.get(entry.updateId) : undefined;
      const id = existing?.id ?? this.core.newId();
      for (let attempt = 0; ; attempt++) {
        try {
          if (existing) {
            await this.putItem(existing.vaultId, id, existing.revision + 1, this.nextVersion(existing, entry.data));
            result.updated++;
          } else {
            await this.putItem(vaultId, id, 1, entry.data);
            result.created++;
          }
          if (++streak >= 20 && limit < maxConcurrency) {
            limit++;
            streak = 0;
          }
          return;
        } catch (error) {
          const retryable =
            error instanceof TypeError || (error instanceof ApiError && (error.status >= 500 || error.status === 429));
          // A create that reached the server before the connection dropped.
          if (attempt > 0 && !existing && error instanceof ApiError && error.code === "conflict") {
            result.created++;
            return;
          }
          if (!retryable || attempt >= 7 || options.signal?.aborted) throw error;
          limit = Math.max(1, Math.floor(limit / 2));
          streak = 0;
          await sleep(Math.min(2000, 50 * 2 ** attempt) * (0.5 + Math.random()));
        }
      }
    };

    const worker = async (index: number) => {
      while (active()) {
        if (index >= limit) {
          await sleep(50);
          continue;
        }
        const entry = entries[next++] as ImportEntry;
        try {
          await save(entry);
        } catch (error) {
          result.failed.push({
            title: entry.data.title,
            error: error instanceof Error ? error.message : String(error),
          });
        }
        done++;
        options.onProgress?.(done, entries.length);
        if (++sinceEmit >= batchSize) {
          sinceEmit = 0;
          this.emit();
          // Let the UI paint between batches.
          await sleep(0);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(maxConcurrency, entries.length) }, (_, i) => worker(i)));
    this.emit();
    if (this.keyring === keyring) await this.sync();
    return result;
  }

  /** Moves an item to the trash. It can be restored for 30 days. */
  async trashItem(id: string): Promise<void> {
    await this.setTrashed(id, Date.now());
  }

  /** Restores an item from the trash. */
  async restoreItem(id: string): Promise<void> {
    await this.setTrashed(id, undefined);
  }

  private async setTrashed(id: string, at: number | undefined) {
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    const { trashedAt: _previous, ...data } = item.data;
    await this.writeItem(item.vaultId, id, item.revision + 1, at === undefined ? data : { ...data, trashedAt: at });
  }

  /**
   * Permanently deletes items that have been in the trash for more than 30
   * days, or every trashed item when `all` is set. Items changed on another
   * device meanwhile are skipped. Returns the number deleted.
   */
  async purgeTrash(all = false): Promise<number> {
    const cutoff = Date.now() - TRASH_RETENTION_MS;
    let deleted = 0;
    for (const item of this.snapshot.trash) {
      if (!all && (item.data.trashedAt ?? Number.POSITIVE_INFINITY) > cutoff) continue;
      try {
        await this.deleteItem(item.id);
        deleted++;
      } catch (error) {
        if (!(error instanceof ConflictError)) throw error;
      }
    }
    return deleted;
  }

  /**
   * Rates a password with the account email (and `extraInputs`, such as an
   * email typed during sign-up) as context.
   */
  estimateStrength(password: string, extraInputs: readonly string[] = []): Strength {
    return estimateStrength(this.core, password, [...this.strengthContext(), ...extraInputs]);
  }

  /** Watchtower analysis of the items outside the trash. */
  health(): VaultHealth {
    return analyzeVault(this.core, this.snapshot.items, this.strengthContext());
  }

  private strengthContext(): string[] {
    const account = this.deviceAccount;
    return account ? [account.email] : [];
  }

  /** Permanently deletes an item on all devices. Prefer `trashItem`. */
  async deleteItem(id: string): Promise<void> {
    const item = this.items.get(id);
    if (!item) return;
    try {
      await this.api.deleteItem(id, item.revision + 1);
    } catch (error) {
      await this.handleWriteError(error);
    }
    this.items.delete(id);
    this.emit();
    await this.sync();
  }

  private async writeItem(vaultId: string, id: string, revision: number, data: ItemData) {
    try {
      await this.putItem(vaultId, id, revision, data);
      this.emit();
    } catch (error) {
      await this.handleWriteError(error);
    }
    await this.sync();
  }

  /** Encrypts and uploads one item version without syncing. */
  private async putItem(vaultId: string, id: string, revision: number, data: ItemData) {
    const keyring = this.requireKeyring();
    const encryptedData = keyring.encryptItem(vaultId, id, revision, JSON.stringify(data));
    const result = await this.api.putItem(id, { vaultId, revision, encryptedData });
    if (this.keyring === keyring) {
      this.items.set(id, { id, vaultId, revision: result.revision, updatedAt: Date.now(), data });
    }
  }

  private async handleWriteError(error: unknown): Promise<never> {
    if (error instanceof ApiError && error.code === "conflict") {
      await this.sync();
      throw new ConflictError();
    }
    throw error;
  }
}
