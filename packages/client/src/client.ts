import {
  type Account,
  type AccountEvent,
  type AccountPreferences,
  type AdminApi,
  ApiError,
  type ClientKind,
  isTwoFactorChallenge,
  type KdfParams,
  type LoginFinishResult,
  type MailLocale,
  type PassboxApi,
  type SecondFactor,
  type SessionInfo,
  type SyncResponse,
  type TwoFactorChallenge,
  type TwoFactorMethod,
  type TwoFactorStatus,
  type WebAuthnRequestOptionsJson,
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
import { type CredentialsContainerLike, createCredential, getAssertion } from "./webauthn";

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

/**
 * Thrown by `signIn`, `unlock`, `reauthenticate` and `changeMasterPassword`
 * when the password was right but the account needs a second factor on this
 * device. The client keeps the login pending (in memory, for 5 minutes):
 * finish it with `completeTwoFactor` or `completeTwoFactorWithSecurityKey`,
 * or drop it with `cancelTwoFactor`.
 */
export class TwoFactorRequiredError extends Error {
  readonly methods: TwoFactorMethod[];
  /** Options for a security key, when the account has one for this site. */
  readonly webauthn: WebAuthnRequestOptionsJson | undefined;
  readonly expiresAt: number;

  constructor(challenge: TwoFactorChallenge) {
    super("This account needs a second factor to sign in.");
    this.name = "TwoFactorRequiredError";
    this.methods = challenge.methods;
    this.webauthn = challenge.webauthn;
    this.expiresAt = challenge.expiresAt;
  }
}

/** The two-factor code, recovery code or security key was not accepted. Try again. */
export class InvalidTwoFactorCodeError extends Error {
  constructor() {
    super("The two-factor code is incorrect.");
    this.name = "InvalidTwoFactorCodeError";
  }
}

/** The pending login expired or was used up; sign in or unlock again. */
export class TwoFactorExpiredError extends Error {
  constructor() {
    super("The sign-in expired. Start again.");
    this.name = "TwoFactorExpiredError";
  }
}

/** The server needs a recent login for this change; call `reauthenticate` first. */
export class ReauthenticationRequiredError extends Error {
  constructor() {
    super("Enter your master password again to confirm this change.");
    this.name = "ReauthenticationRequiredError";
  }
}

/** Maps the server's two-factor error codes to typed errors. */
function twoFactorError(error: unknown): unknown {
  if (!(error instanceof ApiError)) return error;
  switch (error.code) {
    case "invalid_two_factor_code":
      return new InvalidTwoFactorCodeError();
    case "two_factor_expired":
      return new TwoFactorExpiredError();
    case "reauthentication_required":
      return new ReauthenticationRequiredError();
    default:
      return error;
  }
}

/** Why a login runs: it decides what a completed second step does. */
type LoginPurpose = "signIn" | "unlock" | "reauth";

interface PendingTwoFactor {
  account: DeviceAccount;
  keys: Core.MasterKeys;
  challenge: TwoFactorChallenge;
  purpose: LoginPurpose;
}

/** A login counts as recent for this long (the server allows 10 minutes). */
const RECENT_LOGIN_MS = 9 * 60 * 1000;

/** How a second factor for turning two-factor sign-in off is given. */
export type DisableFactor =
  | { method: "totp" | "recovery"; code: string }
  | { method: "webauthn"; credentials?: CredentialsContainerLike };

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
  /**
   * The web origin (`location.origin`) of a browser client, so sign-ins
   * offer the security keys registered for it.
   */
  origin?: string;
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
  private readonly origin: string | undefined;
  /** A login waiting for its second factor. */
  private pending: PendingTwoFactor | undefined;
  /** When the current session token was issued by a full login (ms). */
  private loginAt = 0;
  private keyring: Core.Keyring | undefined;
  /** The account key encrypted with the master keys, kept to verify the master password offline. */
  private accountKeyCiphertext: string | undefined;
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
    this.origin = options.origin;
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

      await this.login(account, keys, "signIn");
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
      await this.sync();
      return { secretKey: account.secretKey, accountId: account.accountId };
    } finally {
      keys.free();
    }
  }

  /**
   * Signs in on a new device with email, master password and Secret Key.
   * Throws `TwoFactorRequiredError` when the account needs a second factor.
   */
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
      await this.login(account, keys, "signIn");
      this.storage.setItem(ACCOUNT_KEY, JSON.stringify(account));
    } finally {
      this.releaseKeys(keys);
    }
    await this.sync();
  }

  /**
   * Unlocks the account remembered on this device. Throws
   * `TwoFactorRequiredError` when the account needs a second factor and
   * this device is not remembered.
   */
  async unlock(password: string): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    const keys = this.deriveKeys(account, password);
    try {
      await this.login(account, keys, "unlock");
    } finally {
      this.releaseKeys(keys);
    }
    await this.sync();
  }

  // --- Two-factor sign-in ----------------------------------------------------------

  /** The login waiting for a second factor, if any. */
  get pendingTwoFactor(): TwoFactorChallenge | undefined {
    return this.pending?.challenge;
  }

  /**
   * Completes the pending login with a 6-digit code or a recovery code.
   * `rememberDevice` skips the second step on this device for 30 days.
   * Throws `InvalidTwoFactorCodeError` (try again) or `TwoFactorExpiredError`
   * (start over). Returns the number of recovery codes left after using one.
   */
  async completeTwoFactor(
    factor: SecondFactor,
    options: { rememberDevice?: boolean } = {},
  ): Promise<{ recoveryCodesRemaining?: number }> {
    const pending = this.pending;
    if (!pending) throw new TwoFactorExpiredError();
    let session: Awaited<ReturnType<PassboxApi["loginTwoFactor"]>>;
    try {
      session = await this.api.loginTwoFactor({
        ...factor,
        challengeToken: pending.challenge.challengeToken,
        rememberDevice: options.rememberDevice ?? false,
      });
    } catch (error) {
      const typed = twoFactorError(error);
      if (typed instanceof TwoFactorExpiredError) this.cancelTwoFactor();
      throw typed;
    }
    this.pending = undefined;
    try {
      if (session.deviceToken) this.storage.setItem(DEVICE_TOKEN_KEY, session.deviceToken);
      await this.useSession(pending.keys, session.token, pending.purpose);
      if (pending.purpose === "signIn") this.storage.setItem(ACCOUNT_KEY, JSON.stringify(pending.account));
    } finally {
      pending.keys.free();
    }
    if (pending.purpose !== "reauth") await this.sync();
    return session.recoveryCodesRemaining === undefined
      ? {}
      : { recoveryCodesRemaining: session.recoveryCodesRemaining };
  }

  /**
   * Completes the pending login with a security key or passkey: asks the
   * browser (`navigator.credentials` unless `credentials` is given) to sign
   * the server's challenge.
   */
  async completeTwoFactorWithSecurityKey(
    options: { rememberDevice?: boolean; credentials?: CredentialsContainerLike; signal?: AbortSignal } = {},
  ): Promise<{ recoveryCodesRemaining?: number }> {
    const request = this.pending?.challenge.webauthn;
    if (!request) throw new TwoFactorExpiredError();
    const webauthn = await getAssertion(options.credentials ?? navigator.credentials, request, options.signal);
    return this.completeTwoFactor(
      { method: "webauthn", webauthn },
      options.rememberDevice === undefined ? {} : { rememberDevice: options.rememberDevice },
    );
  }

  /** Drops the pending login. */
  cancelTwoFactor(): void {
    this.pending?.keys.free();
    this.pending = undefined;
  }

  /**
   * Proves the master password again with a fresh login, for changes the
   * server only accepts from a recent login (adding a second factor, for
   * example). The vault stays unlocked; a wrong password throws
   * `InvalidCredentialsError` without locking. May throw
   * `TwoFactorRequiredError`; then `completeTwoFactor` finishes it.
   */
  async reauthenticate(password: string): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    const keys = await this.checkedKeys(account, password);
    try {
      await this.login(account, keys, "reauth");
    } finally {
      this.releaseKeys(keys);
    }
  }

  /** Whether the session comes from a login recent enough for sensitive changes. */
  get hasRecentLogin(): boolean {
    return this.token !== undefined && Date.now() - this.loginAt < RECENT_LOGIN_MS;
  }

  /** Two-factor status of the account. */
  async twoFactorStatus(): Promise<TwoFactorStatus> {
    this.requireKeyring();
    return this.api.twoFactorStatus();
  }

  /**
   * Starts setting up an authenticator app. Show `uri` as a QR code (and
   * `secret` for typing), then call `confirmTotpSetup` with a first code.
   * Throws `ReauthenticationRequiredError` without a recent login.
   */
  async startTotpSetup(): Promise<{ secret: string; uri: string }> {
    this.requireKeyring();
    return this.twoFactorCall(() => this.api.totpStart());
  }

  /** Turns the authenticator app on. Returns new recovery codes (shown once) if the account had none. */
  async confirmTotpSetup(code: string): Promise<{ recoveryCodes?: string[] }> {
    this.requireKeyring();
    return this.twoFactorCall(() => this.api.totpConfirm(code.replace(/\s/g, "")));
  }

  /** Removes the authenticator app (only while a security key remains). */
  async removeTotp(): Promise<void> {
    this.requireKeyring();
    await this.twoFactorCall(() => this.api.totpRemove());
  }

  /**
   * Registers a security key or passkey as a second factor: the browser asks
   * the user to touch it. Returns new recovery codes if the account had none.
   */
  async addSecurityKey(
    name: string,
    options: { credentials?: CredentialsContainerLike; origin?: string; signal?: AbortSignal } = {},
  ): Promise<{ recoveryCodes?: string[] }> {
    this.requireKeyring();
    const origin = options.origin ?? this.origin ?? globalThis.location?.origin ?? "";
    const { registrationId, publicKey } = await this.twoFactorCall(() => this.api.webauthnRegisterStart(origin));
    const credential = await createCredential(options.credentials ?? navigator.credentials, publicKey, options.signal);
    const result = await this.twoFactorCall(() =>
      this.api.webauthnRegisterFinish({ registrationId, name, credential }),
    );
    return result.recoveryCodes ? { recoveryCodes: result.recoveryCodes } : {};
  }

  /** Removes a security key (only while another second factor remains). */
  async removeSecurityKey(id: string): Promise<void> {
    this.requireKeyring();
    await this.twoFactorCall(() => this.api.webauthnRemove(id));
  }

  /** Replaces all recovery codes with 10 new ones, shown once. */
  async regenerateRecoveryCodes(): Promise<string[]> {
    this.requireKeyring();
    return (await this.twoFactorCall(() => this.api.regenerateRecoveryCodes())).recoveryCodes;
  }

  /**
   * Turns two-factor sign-in off. Needs a current code, a recovery code or
   * the security key (`{ method: "webauthn" }`).
   */
  async disableTwoFactor(factor: DisableFactor): Promise<void> {
    this.requireKeyring();
    if (factor.method !== "webauthn") {
      await this.twoFactorCall(() => this.api.disableTwoFactor(factor));
      return;
    }
    const challenge = await this.twoFactorCall(() => this.api.twoFactorChallenge(this.origin));
    if (!challenge.webauthn) throw new Error("no security key for this site");
    const webauthn = await getAssertion(factor.credentials ?? navigator.credentials, challenge.webauthn);
    await this.twoFactorCall(() =>
      this.api.disableTwoFactor({ method: "webauthn", webauthn, challengeToken: challenge.challengeToken }),
    );
  }

  private async twoFactorCall<T>(call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (error) {
      throw twoFactorError(error);
    }
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
   * Changes the master password. The current password is checked on the
   * device; unless the session comes from a recent login, a fresh login
   * follows (the server only accepts the change from a recent login), which
   * may throw `TwoFactorRequiredError`: complete it and call this again.
   * Vaults and items stay as they are; every other device is signed out.
   */
  async changeMasterPassword(currentPassword: string, newPassword: string): Promise<void> {
    const account = this.deviceAccount;
    if (!account) throw new Error("no account on this device");
    this.requireKeyring();
    const currentKeys = await this.checkedKeys(account, currentPassword);
    try {
      if (!this.hasRecentLogin) await this.login(account, currentKeys, "reauth");
    } finally {
      this.releaseKeys(currentKeys);
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
    this.cancelTwoFactor();
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
    this.loginAt = 0;
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

  /** Frees master keys unless a pending second step still needs them. */
  private releaseKeys(keys: Core.MasterKeys) {
    if (this.pending?.keys !== keys) keys.free();
  }

  /**
   * Derives the master keys and, while unlocked, checks them on the device
   * against the account key, so a typo never reaches the server.
   */
  private async checkedKeys(account: DeviceAccount, password: string): Promise<Core.MasterKeys> {
    const keys = this.deriveKeys(account, password);
    const keyring = this.keyring;
    if (!keyring) return keys;
    try {
      this.accountKeyCiphertext ??= keyring.encryptedAccountKey ?? (await this.api.account()).encryptedAccountKey;
      this.core.Keyring.unlock(keys, account.accountId, this.accountKeyCiphertext).free();
      return keys;
    } catch (error) {
      keys.free();
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    }
  }

  /** Runs the OPAQUE login. Returns a session or the second-factor challenge. */
  private async authenticate(account: DeviceAccount, keys: Core.MasterKeys): Promise<LoginFinishResult> {
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
        ...(this.origin ? { origin: this.origin } : {}),
      });
      if (!isTwoFactorChallenge(finish) && finish.deviceToken) {
        this.storage.setItem(DEVICE_TOKEN_KEY, finish.deviceToken);
      }
      return finish;
    } catch (error) {
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
    } finally {
      flow.free();
    }
  }

  /**
   * Runs the OPAQUE login and unlocks the keyring (or, to reauthenticate,
   * only replaces the session token). When the account needs a second
   * factor, keeps `keys` for the pending login and throws
   * `TwoFactorRequiredError`.
   */
  private async login(account: DeviceAccount, keys: Core.MasterKeys, purpose: LoginPurpose): Promise<void> {
    let result: LoginFinishResult;
    try {
      result = await this.authenticate(account, keys);
    } catch (error) {
      if (purpose !== "reauth") this.clearSession();
      throw error;
    }
    if (isTwoFactorChallenge(result)) {
      if (purpose !== "reauth") this.clearSession();
      this.cancelTwoFactor();
      this.pending = { account, keys, challenge: result, purpose };
      if (purpose !== "reauth") this.emit();
      throw new TwoFactorRequiredError(result);
    }
    await this.useSession(keys, result.token, purpose);
  }

  /** Takes a session token from a complete login. */
  private async useSession(keys: Core.MasterKeys, token: string, purpose: LoginPurpose) {
    if (purpose === "reauth") {
      this.token = token;
      this.loginAt = Date.now();
      return;
    }
    try {
      this.clearSession();
      this.token = token;
      const remote = await this.api.account();
      this.keyring = this.core.Keyring.unlock(keys, remote.accountId, remote.encryptedAccountKey);
      this.accountKeyCiphertext = remote.encryptedAccountKey;
      this.loginAt = Date.now();
    } catch (error) {
      this.clearSession();
      throw isInvalidCredentials(error) ? new InvalidCredentialsError() : error;
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
