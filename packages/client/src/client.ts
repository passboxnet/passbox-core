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
import { type ItemData, parseItemData, parseVaultMeta } from "./items";
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

export interface ClientSnapshot {
  status: ClientStatus;
  email: string | undefined;
  vaults: Vault[];
  items: Item[];
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
      items: [...this.items.values()].sort((a, b) => a.data.title.localeCompare(b.data.title)),
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
      const start = await this.api.loginStart({ email: account.email, credentialRequest: flow.request });
      const credentialFinalization = flow.finish(start.credentialResponse);
      const { token } = await this.api.loginFinish({
        loginId: start.loginId,
        credentialFinalization,
        ...(this.device ? { deviceName: this.device.name, clientKind: this.device.kind } : {}),
      });
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

  /** Saves a new version of an existing item. */
  async updateItem(id: string, data: ItemData): Promise<void> {
    const item = this.items.get(id);
    if (!item) throw new Error("unknown item");
    await this.writeItem(item.vaultId, id, item.revision + 1, data);
  }

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
    const keyring = this.requireKeyring();
    const encryptedData = keyring.encryptItem(vaultId, id, revision, JSON.stringify(data));
    try {
      const result = await this.api.putItem(id, { vaultId, revision, encryptedData });
      this.items.set(id, { id, vaultId, revision: result.revision, updatedAt: Date.now(), data });
      this.emit();
    } catch (error) {
      await this.handleWriteError(error);
    }
    await this.sync();
  }

  private async handleWriteError(error: unknown): Promise<never> {
    if (error instanceof ApiError && error.code === "conflict") {
      await this.sync();
      throw new ConflictError();
    }
    throw error;
  }
}
