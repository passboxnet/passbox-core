import {
  type Account,
  type AccountEvent,
  type AccountKeys,
  type AccountPreferences,
  type AdminApi,
  ApiError,
  type ClientKind,
  type InvitationPreview,
  type KdfParams,
  type MailLocale,
  type OrgInvitationInfo,
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
import {
  type Invitation,
  type KeyLookup,
  type Org,
  type OrgGroup,
  type OrgRole,
  type PrincipalType,
  parseInvitationLink,
  type SharedVault,
  type SharingReport,
  type SharingView,
  type SharingWarning,
  type VaultAccess,
  type VaultRole,
} from "./sharing";
import type { KeyValueStorage } from "./storage";

type CoreModule = typeof Core;

const EMPTY_SHARING: SharingView = { orgs: [], vaults: [], warnings: [] };

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
  /** The organization of a shared vault; `undefined` for personal vaults. */
  orgId?: string;
  /** Current key epoch (0 or absent for personal vaults). */
  keyEpoch?: number;
  /** This account's verified role: personal vaults are `manage`. */
  role?: VaultRole | undefined;
}

export interface Item {
  id: string;
  vaultId: string;
  revision: number;
  updatedAt: number;
  /** Vault key epoch the item is encrypted with (0 or absent for personal vaults). */
  keyEpoch?: number;
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
  /** Organizations with verified members and groups. */
  orgs: Org[];
  /** Shared vaults with verified members and roles. */
  sharedVaults: SharedVault[];
  /** Problems found while verifying sharing data, for example changed keys. */
  sharingWarnings: SharingWarning[];
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
 * Sharing trust store (pinned keys, organization fingerprints, verified key
 * directory head, manifest versions), per account. Public data whose
 * integrity matters: a changed copy could hide a key change.
 */
const TRUST_KEY = "passbox.trust";
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
  /** Origin of the web app for invitation links, for example `https://passbox.example.com`. */
  linkBase?: string;
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
  private readonly linkBase: string | undefined;
  private keyring: Core.Keyring | undefined;
  /** The account key encrypted with the master keys, kept to verify the master password offline. */
  private accountKeyCiphertext: string | undefined;
  private cursor = 0;
  private vaults = new Map<string, Vault>();
  private items = new Map<string, Item>();
  private errors = new Map<string, string>();
  private sharingView: SharingView = EMPTY_SHARING;
  private listeners = new Set<() => void>();
  private snapshot: ClientSnapshot;
  /** Session token of the current unlock. */
  token: string | undefined;

  constructor(options: PassboxClientOptions) {
    this.core = options.core;
    this.api = options.api;
    this.storage = options.storage;
    this.device = options.device;
    this.linkBase = options.linkBase;
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
    const sharing = this.sharingView;
    const roles = new Map(sharing.vaults.map((v) => [v.vaultId, v.role ?? undefined]));
    return {
      status: this.keyring ? "unlocked" : account ? "locked" : "signed-out",
      email: account?.email,
      vaults: [...this.vaults.values()]
        .map((vault) => ({ ...vault, role: vault.orgId ? roles.get(vault.id) : ("manage" as const) }))
        .sort((a, b) => a.name.localeCompare(b.name)),
      orgs: sharing.orgs,
      sharedVaults: sharing.vaults,
      sharingWarnings: sharing.warnings,
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
   *
   * `inviteToken` comes from an invitation link and is needed when the server
   * only allows invited accounts; `locale` is the language of mails.
   */
  async signUp(
    email: string,
    password: string,
    options: { inviteToken?: string; locale?: MailLocale } = {},
  ): Promise<{ secretKey: string; accountId: string }> {
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
        ...(options.inviteToken ? { inviteToken: options.inviteToken } : {}),
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
        ...(options.inviteToken ? { inviteToken: options.inviteToken } : {}),
        ...(options.locale ? { locale: options.locale } : {}),
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

  /** The account as the server sees it, including whether it is an instance admin. */
  async accountInfo(): Promise<Account> {
    this.requireKeyring();
    return this.api.account();
  }

  /** Mail language and notification settings stored on the server. */
  async preferences(): Promise<AccountPreferences> {
    this.requireKeyring();
    return this.api.preferences();
  }

  async updatePreferences(changes: {
    locale?: MailLocale | "";
    notifyNewDevice?: boolean;
  }): Promise<AccountPreferences> {
    this.requireKeyring();
    return this.api.updatePreferences(changes);
  }

  /**
   * Instance administration (settings, accounts, mail, invitations, audit
   * log). The server answers 403 `forbidden` unless the account is an
   * instance admin.
   */
  get admin(): AdminApi {
    this.requireKeyring();
    return this.api;
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
      const encryptedAccountKey = keyring.wrapAccountKey(newKeys);
      await this.api.passwordChangeFinish({
        registrationUpload,
        kdfSalt: next.kdfSalt,
        kdfParams: next.kdfParams,
        encryptedAccountKey,
      });
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(next));
      this.accountKeyCiphertext = encryptedAccountKey;
    } finally {
      newKeys.free();
    }
  }

  /**
   * Checks the master password without contacting the server: derives the
   * keys locally and tries to open the account key with them. Use it to
   * confirm the user before showing the Emergency Kit or other sensitive
   * screens. Requires an unlocked vault.
   */
  async verifyMasterPassword(password: string): Promise<boolean> {
    const keyring = this.requireKeyring();
    const account = this.deviceAccount;
    if (!account) return false;
    // A resumed session (`restoreSession`) has no ciphertext yet; fetch it once.
    this.accountKeyCiphertext ??= keyring.encryptedAccountKey ?? (await this.api.account()).encryptedAccountKey;
    let keys: Core.MasterKeys;
    try {
      keys = this.deriveKeys(account, password);
    } catch (error) {
      if (error instanceof InvalidCredentialsError) return false;
      throw error;
    }
    try {
      this.core.Keyring.unlock(keys, account.accountId, this.accountKeyCiphertext).free();
      return true;
    } catch (error) {
      if (isInvalidCredentials(error)) return false;
      throw error;
    } finally {
      keys.free();
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
    this.loadTrust(this.keyring, state.accountId);
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
    this.accountKeyCiphertext = undefined;
    this.token = undefined;
    this.cursor = 0;
    this.vaults.clear();
    this.items.clear();
    this.errors.clear();
    this.sharingView = EMPTY_SHARING;
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
      this.loadTrust(this.keyring, remote.accountId);
      this.accountKeyCiphertext = remote.encryptedAccountKey;
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
    await this.ensureAccountKeys(keyring);
    const since = this.cursor;
    const delta = await this.api.sync(since, { sharing: true });
    if (this.keyring !== keyring) return; // locked meanwhile
    const missingKey = await this.apply(keyring, delta);
    if (missingKey && since !== 0 && this.keyring === keyring) {
      // A shared vault's key could not be opened: fetch everything again once.
      const full = await this.api.sync(0, { sharing: true });
      if (this.keyring !== keyring) return;
      await this.apply(keyring, full);
    }
    this.emit();
  }

  /** Loads the account's key pairs, creating and publishing them on the first unlock after the update. */
  private async ensureAccountKeys(keyring: Core.Keyring): Promise<void> {
    if (keyring.hasAccountKeys()) return;
    let keys: AccountKeys | undefined;
    try {
      keys = await this.api.sharing.ownKeys();
    } catch (error) {
      if (!(error instanceof ApiError && error.status === 404)) throw error;
    }
    if (this.keyring !== keyring || keyring.hasAccountKeys()) return;
    if (keys) {
      keyring.loadAccountKeys(keys.bundle, keys.bundleSignature, keys.encryptedPrivate);
    } else {
      const upload = JSON.parse(keyring.createAccountKeys(Date.now())) as AccountKeys;
      await this.api.sharing.publishKeys(upload);
    }
  }

  private loadTrust(keyring: Core.Keyring, accountId: string) {
    const raw = this.storage.getItem(`${TRUST_KEY}.${accountId}`);
    if (!raw) return;
    try {
      keyring.setTrustStore(raw);
    } catch {
      // An unreadable trust store starts over (trust on first use).
    }
  }

  private saveTrust(keyring: Core.Keyring) {
    this.storage.setItem(`${TRUST_KEY}.${keyring.accountId}`, keyring.trustStore());
  }

  /** Applies a sync delta. Returns whether a verified shared vault is missing its current key. */
  private async apply(keyring: Core.Keyring, delta: SyncResponse): Promise<boolean> {
    let uploads: SharingReport["wrappedKeys"] = [];
    if (delta.sharing) {
      const report = JSON.parse(keyring.applySharing(JSON.stringify(delta.sharing))) as SharingReport;
      this.sharingView = report.view;
      uploads = report.wrappedKeys;
      this.saveTrust(keyring);
      const accessible = new Set(report.view.vaults.map((v) => v.vaultId));
      for (const vault of [...this.vaults.values()]) {
        if (vault.orgId && !accessible.has(vault.id)) {
          this.vaults.delete(vault.id);
          for (const item of [...this.items.values()]) if (item.vaultId === vault.id) this.items.delete(item.id);
        }
      }
    }
    for (const vault of delta.vaults) {
      const keyEpoch = vault.keyEpoch ?? 0;
      try {
        if (!vault.orgId && !keyring.hasVault(vault.id)) keyring.addVault(vault.id, vault.encryptedKey);
        const meta = parseVaultMeta(keyring.decryptVaultMetaAt(vault.id, keyEpoch, vault.encryptedMeta));
        this.vaults.set(vault.id, {
          id: vault.id,
          name: meta.name,
          revision: vault.revision,
          keyEpoch,
          ...(vault.orgId ? { orgId: vault.orgId } : {}),
        });
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
        const keyEpoch = item.keyEpoch ?? 0;
        const json = keyring.decryptItemAt(item.vaultId, keyEpoch, item.id, item.revision, item.encryptedData);
        this.items.set(item.id, {
          id: item.id,
          vaultId: item.vaultId,
          revision: item.revision,
          updatedAt: item.updatedAt,
          keyEpoch,
          data: parseItemData(json),
        });
        this.errors.delete(item.id);
      } catch (error) {
        this.items.delete(item.id);
        this.errors.set(item.id, `Item ${item.id} could not be decrypted: ${String(error)}`);
      }
    }
    this.cursor = Math.max(this.cursor, delta.cursor);
    // Own copies of newly opened vault keys; best effort.
    for (const upload of uploads) {
      await this.api.sharing.putWrappedKey(upload.vaultId, upload.keyEpoch, upload.wrappedKey).catch(() => undefined);
    }
    return this.sharingView.vaults.some((v) => v.verified && !v.hasKey);
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
        encryptedMeta: keyring.encryptVaultMetaAt(id, vault.keyEpoch ?? 0, JSON.stringify({ name })),
        ...(vault.orgId ? { keyEpoch: vault.keyEpoch ?? 0 } : {}),
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
    const keyEpoch = this.vaults.get(vaultId)?.keyEpoch ?? 0;
    const encryptedData = keyring.encryptItemAt(vaultId, keyEpoch, id, revision, JSON.stringify(data));
    const result = await this.api.putItem(id, {
      vaultId,
      revision,
      encryptedData,
      ...(keyEpoch ? { keyEpoch } : {}),
    });
    if (this.keyring === keyring) {
      this.items.set(id, { id, vaultId, revision: result.revision, updatedAt: Date.now(), keyEpoch, data });
    }
  }

  // --- Organizations and sharing -------------------------------------------------
  //
  // Signing, sealing and verification happen in the Rust core (WebAssembly);
  // these methods run the HTTP calls and multi-step flows. See
  // docs/architecture/sharing.md.

  private viewNow(): SharingView {
    return this.sharingView;
  }

  /** Organizations with verified members and groups. */
  orgs(): Org[] {
    return this.viewNow().orgs;
  }

  /** One organization; throws if unknown. */
  org(orgId: string): Org {
    const org = this.viewNow().orgs.find((o) => o.id === orgId);
    if (!org) throw new Error("unknown organization");
    return org;
  }

  /** Shared vaults with verified members, roles and key state. */
  sharedVaults(): SharedVault[] {
    return this.viewNow().vaults;
  }

  /** Problems found while verifying sharing data (for example `key_changed`). */
  sharingWarnings(): SharingWarning[] {
    return this.viewNow().warnings;
  }

  /** Ownership and this account's role for a vault. */
  vaultAccess(vaultId: string): VaultAccess {
    const shared = this.viewNow().vaults.find((v) => v.vaultId === vaultId);
    if (shared) {
      return { vaultId, orgId: shared.orgId, role: shared.role ?? undefined, verified: shared.verified };
    }
    const vault = this.vaults.get(vaultId);
    if (vault && !vault.orgId) return { vaultId, orgId: undefined, role: "manage", verified: true };
    throw new Error("unknown vault");
  }

  /** Fingerprint of this account's own keys, for comparing with others. */
  ownFingerprint(): string {
    const fingerprint = this.requireKeyring().ownFingerprint();
    if (!fingerprint) throw new Error("the account has no key pairs yet");
    return fingerprint;
  }

  /**
   * Looks up an account's key in the key directory and verifies the proof.
   * New keys are pinned; `status: "changed"` must be accepted with `acceptKeyChange`.
   */
  async lookupKey(accountId: string): Promise<KeyLookup> {
    const keyring = this.requireKeyring();
    const since = (JSON.parse(keyring.trustStore()) as { directory?: { size?: number } }).directory?.size ?? 0;
    const response = await this.api.sharing.lookupKey(accountId, since);
    const lookup = JSON.parse(keyring.verifyDirectoryLookup(accountId, JSON.stringify(response))) as KeyLookup;
    this.saveTrust(keyring);
    return lookup;
  }

  /** Checks that the key directory lists this account's own key. */
  async verifyOwnKey(): Promise<KeyLookup> {
    return this.lookupKey(this.requireKeyring().accountId);
  }

  /** Trusts the current key of an account after a change. Returns its fingerprint. */
  acceptKeyChange(accountId: string): string {
    const keyring = this.requireKeyring();
    const fingerprint = keyring.acceptKeyChange(accountId);
    this.saveTrust(keyring);
    this.sharingView = JSON.parse(keyring.sharingView()) as SharingView;
    this.emit();
    return fingerprint;
  }

  /** Creates a family organization with its shared family vault. Returns the organization ID. */
  async createFamily(name: string, vaultName: string): Promise<string> {
    return this.createOrg("family", name, vaultName);
  }

  /** Creates a team organization. Returns its ID. */
  async createTeam(name: string): Promise<string> {
    return this.createOrg("team", name, undefined);
  }

  private async createOrg(kind: "family" | "team", name: string, vaultName: string | undefined): Promise<string> {
    await this.sync();
    const keyring = this.requireKeyring();
    const body = JSON.parse(
      keyring.createOrg(
        kind,
        JSON.stringify({ name }),
        vaultName === undefined ? undefined : JSON.stringify({ name: vaultName }),
        Date.now(),
      ),
    ) as { id: string };
    await this.api.sharing.createOrg(body);
    await this.sync();
    return body.id;
  }

  /** Renames an organization (admins). */
  async renameOrg(orgId: string, name: string): Promise<void> {
    const keyring = this.requireKeyring();
    const org = await this.orgRecord(orgId);
    await this.api.sharing.updateOrg(orgId, {
      revision: org.revision + 1,
      metaEpoch: org.metaEpoch,
      encryptedMeta: keyring.encryptOrgMeta(orgId, org.metaEpoch, JSON.stringify({ name })),
    });
    await this.sync();
  }

  private async orgRecord(orgId: string): Promise<{ revision: number; metaEpoch: number }> {
    const delta = await this.api.sync(this.cursor, { sharing: true });
    const orgs = (delta.sharing?.orgs ?? []) as { id: string; revision: number; metaEpoch: number }[];
    const org = orgs.find((o) => o.id === orgId);
    if (!org) throw new Error("unknown organization");
    return org;
  }

  /** Deletes an organization with all its vaults (owner only). */
  async deleteOrg(orgId: string): Promise<void> {
    await this.api.sharing.deleteOrg(orgId);
    await this.sync();
  }

  /**
   * Invites someone by email. Returns the link (with the organization
   * fingerprint); the server also mails it when a mailer is configured.
   * `linkBase` defaults to the API base URL (the web app's origin).
   */
  async invite(orgId: string, email: string, role: Exclude<OrgRole, "owner">, linkBase?: string): Promise<Invitation> {
    const keyring = this.requireKeyring();
    const [root] = JSON.parse(keyring.orgFingerprint(orgId)) as [string, string];
    const linkFragment = `org=${root}`;
    const created = await this.api.sharing.invite(orgId, { email, role, linkFragment });
    const base = (linkBase ?? this.linkBase ?? "").replace(/\/+$/, "");
    return {
      id: created.id,
      token: created.token,
      link: `${base}${created.path}#${linkFragment}`,
      expiresAt: created.expiresAt,
    };
  }

  /** Pending invitations (admins). */
  async invitations(orgId: string): Promise<OrgInvitationInfo[]> {
    return this.api.sharing.invitations(orgId);
  }

  async revokeInvitation(orgId: string, invitationId: string): Promise<void> {
    await this.api.sharing.revokeInvitation(orgId, invitationId);
  }

  /** What an invitation link (or token) is for; works before signing in. */
  async previewInvitation(link: string): Promise<InvitationPreview> {
    return this.api.sharing.previewInvitation(parseInvitationLink(link).token);
  }

  /**
   * Accepts an invitation for the signed-in account (which must have the
   * invited email) and returns the organization ID. The organization
   * fingerprint in the link is pinned. Membership stays `accepted` until an
   * admin confirms it.
   */
  async acceptInvitation(link: string): Promise<string> {
    const { token, orgRoot } = parseInvitationLink(link);
    await this.sync();
    const preview = await this.api.sharing.previewInvitation(token);
    const keyring = this.requireKeyring();
    if (orgRoot) {
      keyring.pinOrgRoot(preview.orgId, orgRoot);
      this.saveTrust(keyring);
    }
    const accepted = await this.api.sharing.acceptInvitation(token);
    await this.sync();
    return accepted.orgId;
  }

  /**
   * Confirms a member who accepted an invitation (admins): verifies their key
   * in the key directory, attests it and seals the organization key. In a
   * family the member also gets the family vault (edit). Returns the attested
   * fingerprint for optional comparison with the member.
   */
  async confirmMember(orgId: string, accountId: string): Promise<string> {
    await this.sync();
    const lookup = await this.lookupKey(accountId);
    if (lookup.status === "changed") throw new Error("the member's key changed; compare fingerprints first");
    const keyring = this.requireKeyring();
    const body = JSON.parse(keyring.confirmMember(orgId, accountId, Date.now())) as { fingerprint: string };
    await this.api.sharing.confirmMember(orgId, accountId, body);
    await this.sync();
    const org = this.org(orgId);
    const vaultId = org.defaultVaultId;
    if (
      org.kind === "family" &&
      vaultId &&
      this.sharedVaults().some((v) => v.vaultId === vaultId && v.role === "manage")
    ) {
      await this.shareVault(vaultId, "account", accountId, "edit");
    }
    return body.fingerprint;
  }

  /** Changes a member's role (admins; admin rights only by the owner). */
  async setMemberRole(orgId: string, accountId: string, role: Exclude<OrgRole, "owner">): Promise<void> {
    const body = JSON.parse(this.requireKeyring().setMemberRole(orgId, accountId, role, Date.now()));
    await this.api.sharing.updateMember(orgId, accountId, body);
    await this.sync();
  }

  /** Blocks a member on the server (not cryptographic; `removeMember` rotates keys). */
  async suspendMember(orgId: string, accountId: string): Promise<void> {
    await this.api.sharing.suspendMember(orgId, accountId);
    await this.sync();
  }

  async reactivateMember(orgId: string, accountId: string): Promise<void> {
    await this.api.sharing.reactivateMember(orgId, accountId);
    await this.sync();
  }

  /**
   * Removes a member and rotates every key they had: their groups, the vaults
   * they could open (items re-encrypted) and the organization key; members
   * they attested are re-attested. Vaults this account cannot manage stay
   * `rotationPending` for their managers.
   */
  async removeMember(orgId: string, accountId: string): Promise<void> {
    await this.sync();
    const attestations = JSON.parse(this.requireKeyring().reattestMembers(orgId, accountId, Date.now())) as {
      accountId: string;
    }[];
    const removed = await this.api.sharing.removeMember(orgId, accountId);
    await this.sync();
    for (const groupId of removed.groups) {
      if (this.org(orgId).groups.some((g) => g.id === groupId && g.isMember)) {
        await this.rotateGroup(orgId, groupId, [accountId]);
      }
    }
    await this.sync();
    await this.rotatePendingVaults(orgId, [["account", accountId]]);
    for (const attestation of attestations) {
      await this.api.sharing.updateMember(orgId, attestation.accountId, attestation);
    }
    await this.sync();
    await this.api.sharing.rotateOrgKey(orgId, JSON.parse(this.requireKeyring().rotateOrgKey(orgId, Date.now())));
    await this.sync();
  }

  /** Leaves an organization (not possible for its owner). */
  async leaveOrg(orgId: string): Promise<void> {
    await this.api.sharing.removeMember(orgId, this.requireKeyring().accountId);
    await this.sync();
  }

  /** Creates a shared vault in an organization (owners and admins). Returns its ID. */
  async createSharedVault(orgId: string, name: string): Promise<string> {
    const body = JSON.parse(this.requireKeyring().createSharedVault(orgId, JSON.stringify({ name }), Date.now())) as {
      id: string;
    };
    await this.api.sharing.createSharedVault(orgId, body);
    await this.sync();
    return body.id;
  }

  /**
   * Shares a vault with an account or group, or changes a member's role.
   * Refused while the member's key changed and the change was not accepted.
   */
  async shareVault(vaultId: string, principalType: PrincipalType, principalId: string, role: VaultRole): Promise<void> {
    const body = JSON.parse(this.requireKeyring().shareVault(vaultId, principalType, principalId, role, Date.now()));
    await this.api.sharing.putVaultMember(vaultId, body);
    await this.sync();
  }

  /**
   * Removes a member from a vault: rotates the vault key and re-encrypts every
   * item, so the former member cannot read anything added later (they may
   * have kept what they saw).
   */
  async unshareVault(vaultId: string, principalType: PrincipalType, principalId: string): Promise<void> {
    await this.rotateVaultKey(vaultId, [[principalType, principalId]]);
  }

  /** Verified members of a shared vault. */
  vaultMembers(vaultId: string): SharedVault {
    const vault = this.sharedVaults().find((v) => v.vaultId === vaultId);
    if (!vault) throw new Error("unknown vault");
    return vault;
  }

  /** Rotates the vaults of an organization marked for rotation that this account manages. */
  async rotatePendingVaults(orgId: string, removed: [PrincipalType, string][] = []): Promise<void> {
    const pending = this.sharedVaults().filter(
      (v) => v.orgId === orgId && v.rotationPending && v.hasKey && v.role === "manage",
    );
    for (const vault of pending) await this.rotateVaultKey(vault.vaultId, removed);
  }

  /** Rotates a vault's key (without `removed`) and re-encrypts its items. */
  async rotateVaultKey(vaultId: string, removed: [PrincipalType, string][] = []): Promise<void> {
    await this.sync();
    const vault = this.vaults.get(vaultId);
    if (!vault) throw new Error("unknown vault");
    const body = JSON.parse(
      this.requireKeyring().rotateVault(
        vaultId,
        JSON.stringify(removed),
        JSON.stringify({ name: vault.name }),
        Date.now(),
      ),
    ) as { keyEpoch: number };
    await this.api.sharing.rotateVault(vaultId, body);
    await this.sync();
    await this.reencryptVault(vaultId, body.keyEpoch);
  }

  /** Re-encrypts the items of a vault still at an older key epoch, 100 per request. */
  async reencryptVault(vaultId: string, keyEpoch: number): Promise<void> {
    for (let attempt = 0; attempt < 2; attempt++) {
      const keyring = this.requireKeyring();
      const stale = [...this.items.values()].filter((i) => i.vaultId === vaultId && (i.keyEpoch ?? 0) < keyEpoch);
      if (stale.length === 0) return;
      for (let i = 0; i < stale.length; i += 100) {
        const batch = stale.slice(i, i + 100).map((item) => ({
          id: item.id,
          revision: item.revision + 1,
          keyEpoch,
          encryptedData: keyring.encryptItemAt(
            vaultId,
            keyEpoch,
            item.id,
            item.revision + 1,
            JSON.stringify(item.data),
          ),
        }));
        await this.api.sharing.reencryptItems(vaultId, batch);
      }
      await this.sync();
    }
  }

  /** Groups of an organization. */
  groups(orgId: string): OrgGroup[] {
    return this.org(orgId).groups;
  }

  /** Creates a group (admins); the creator is always a member. Returns its ID. */
  async createGroup(orgId: string, name: string, members: string[] = []): Promise<string> {
    const body = JSON.parse(
      this.requireKeyring().createGroup(orgId, JSON.stringify({ name }), JSON.stringify(members), Date.now()),
    ) as { id: string };
    await this.api.sharing.createGroup(orgId, body);
    await this.sync();
    return body.id;
  }

  async renameGroup(orgId: string, groupId: string, name: string): Promise<void> {
    const { metaEpoch } = await this.orgRecord(orgId);
    await this.api.sharing.updateGroup(orgId, groupId, {
      metaEpoch,
      encryptedMeta: this.requireKeyring().encryptGroupMeta(orgId, groupId, metaEpoch, JSON.stringify({ name })),
    });
    await this.sync();
  }

  /** Deletes a group (admins). Unshare its vaults first. */
  async deleteGroup(orgId: string, groupId: string): Promise<void> {
    await this.api.sharing.deleteGroup(orgId, groupId);
    await this.sync();
  }

  /** Adds a member to a group: one sealing of the group key. */
  async addGroupMember(orgId: string, groupId: string, accountId: string): Promise<void> {
    const body = JSON.parse(this.requireKeyring().addGroupMember(groupId, accountId, Date.now()));
    await this.api.sharing.addGroupMember(orgId, groupId, body);
    await this.sync();
  }

  /** Removes a member from a group: rotates the group key and the vaults shared with the group. */
  async removeGroupMember(orgId: string, groupId: string, accountId: string): Promise<void> {
    await this.rotateGroup(orgId, groupId, [accountId]);
    await this.sync();
    await this.rotatePendingVaults(orgId);
  }

  private async rotateGroup(orgId: string, groupId: string, removed: string[]): Promise<void> {
    const body = JSON.parse(this.requireKeyring().rotateGroup(groupId, JSON.stringify(removed), Date.now()));
    await this.api.sharing.rotateGroup(orgId, groupId, body);
  }

  private async handleWriteError(error: unknown): Promise<never> {
    if (error instanceof ApiError && error.code === "conflict") {
      await this.sync();
      throw new ConflictError();
    }
    throw error;
  }
}
