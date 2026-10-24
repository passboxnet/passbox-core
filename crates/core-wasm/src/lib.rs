//! WebAssembly bindings for the Passbox core, used by the web client and the
//! browser extension.
//!
//! Secret material (master keys, account and vault keys, OPAQUE state) stays
//! inside WebAssembly objects. JavaScript only sees ciphertexts, protocol
//! messages and the decrypted JSON it needs to display. Call `free()` on
//! objects holding secrets when they are no longer needed; their memory is
//! wiped on drop.
//!
//! Build with `pnpm --filter @passbox/core-wasm build`.

use passbox_core::aead::{KEY_LEN, SymmetricKey};
use passbox_core::generator::{self, PassphraseOptions, PasswordOptions};
use passbox_core::kdf::{self, KdfParams, MasterKeys as CoreMasterKeys};
use passbox_core::keyring::Keyring as CoreKeyring;
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::passkey::{self, Flags};
use passbox_core::secret_key::SecretKey;
use passbox_core::strength;
use passbox_core::totp::Totp;
use passbox_core::{Error, encoding, id};
use wasm_bindgen::prelude::*;

/// Converts a core error into a JavaScript `Error`. Wrong credentials get the
/// name `InvalidCredentialsError` so callers can tell them apart.
fn js_error(err: Error) -> JsValue {
    let error = js_sys::Error::new(&err.to_string());
    if err == Error::InvalidCredentials {
        error.set_name("InvalidCredentialsError");
    }
    error.into()
}

fn json_error(err: serde_json::Error) -> JsValue {
    js_sys::Error::new(&format!("invalid JSON: {err}")).into()
}

fn revision(value: f64) -> Result<u64, JsValue> {
    if value.fract() == 0.0 && (1.0..=9_007_199_254_740_991.0).contains(&value) {
        Ok(value as u64)
    } else {
        Err(js_sys::Error::new("revision must be a positive integer").into())
    }
}

// --- Utilities ----------------------------------------------------------------

/// Generates a password. `options_json` is a JSON object matching `PasswordOptions`;
/// missing fields use the defaults.
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(options_json: &str) -> Result<String, JsValue> {
    let options: PasswordOptions = serde_json::from_str(options_json).map_err(json_error)?;
    generator::generate_password(&options).map_err(js_error)
}

/// Generates a word passphrase. `options_json` is a `PassphraseOptions`
/// object (`words`, `separator`, `capitalize`, `includeDigit`).
#[wasm_bindgen(js_name = generatePassphrase)]
pub fn generate_passphrase(options_json: &str) -> Result<String, JsValue> {
    let options: PassphraseOptions = serde_json::from_str(options_json).map_err(json_error)?;
    generator::generate_passphrase(&options).map_err(js_error)
}

/// Estimates password strength. `user_inputs_json` is a JSON array of
/// strings an attacker would try first (email, name). Returns JSON:
/// `{"score":0-4,"bits":n,"warning":code|null,"suggestions":[codes],
/// "acceptableMasterPassword":bool}`.
#[wasm_bindgen(js_name = estimateStrength)]
pub fn estimate_strength(password: &str, user_inputs_json: &str) -> Result<String, JsValue> {
    let inputs: Vec<String> = serde_json::from_str(user_inputs_json).map_err(json_error)?;
    let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let estimate = strength::estimate(password, &inputs);
    Ok(serde_json::json!({
        "score": estimate.score,
        "bits": estimate.bits,
        "warning": estimate.warning,
        "suggestions": estimate.suggestions,
        "acceptableMasterPassword": strength::is_acceptable_master_password(password, &estimate),
    })
    .to_string())
}

/// Checks a one-time password field: `undefined` when fine or empty,
/// `"one_time_code"` for a single code instead of the setup key, or
/// `"invalid"`.
#[wasm_bindgen(js_name = totpInputProblem)]
pub fn totp_input_problem(input: &str) -> Option<String> {
    Totp::input_problem(input).map(str::to_owned)
}

/// Generates a new Secret Key in display format.
#[wasm_bindgen(js_name = generateSecretKey)]
pub fn generate_secret_key() -> Result<String, JsValue> {
    Ok(SecretKey::generate().map_err(js_error)?.to_display_string())
}

/// Returns the normalized display format of a Secret Key, or throws if it is invalid.
#[wasm_bindgen(js_name = normalizeSecretKey)]
pub fn normalize_secret_key(input: &str) -> Result<String, JsValue> {
    Ok(SecretKey::parse(input)
        .map_err(js_error)?
        .to_display_string())
}

/// Creates a new random ID for accounts, vaults and items.
#[wasm_bindgen(js_name = newId)]
pub fn new_id() -> Result<String, JsValue> {
    id::new_id().map_err(js_error)
}

/// Generates a new KDF salt (Base64url).
#[wasm_bindgen(js_name = generateKdfSalt)]
pub fn generate_kdf_salt() -> Result<String, JsValue> {
    Ok(encoding::encode(&kdf::generate_salt().map_err(js_error)?))
}

/// The KDF parameters for new accounts, as JSON.
#[wasm_bindgen(js_name = defaultKdfParams)]
pub fn default_kdf_params() -> String {
    serde_json::to_string(&KdfParams::DEFAULT).expect("KdfParams serialize")
}

/// Generates the TOTP code for an `otpauth://` URI or a Base32 secret at `unix_time` seconds.
#[wasm_bindgen(js_name = totpCode)]
pub fn totp_code(uri_or_secret: &str, unix_time: f64) -> Result<String, JsValue> {
    let totp = Totp::parse(uri_or_secret).map_err(js_error)?;
    // Time values from JavaScript are non-negative and well within u64 range.
    Ok(totp.generate(unix_time.max(0.0) as u64))
}

// --- Passkeys ----------------------------------------------------------------

/// Creates an ES256 passkey for `rp_id`. The caller must have checked the
/// relying party ID against the requesting origin. Returns JSON with Base64url
/// values: `{ credentialId, privateKey (PKCS#8), publicKeyCose, publicKeySpki,
/// authenticatorData, attestationObject, algorithm }`.
#[wasm_bindgen(js_name = passkeyCreate)]
pub fn passkey_create(rp_id: &str) -> Result<String, JsValue> {
    let created = passkey::create(rp_id, Flags::SYNCED).map_err(js_error)?;
    Ok(serde_json::json!({
        "credentialId": encoding::encode(&created.credential_id),
        "privateKey": encoding::encode(&created.private_key_pkcs8),
        "publicKeyCose": encoding::encode(&created.public_key_cose),
        "publicKeySpki": encoding::encode(&created.public_key_spki),
        "authenticatorData": encoding::encode(&created.authenticator_data),
        "attestationObject": encoding::encode(&created.attestation_object),
        "algorithm": passkey::ALG_ES256,
    })
    .to_string())
}

/// Signs a WebAuthn assertion with a stored passkey (`private_key`: PKCS#8,
/// Base64url) over `authenticatorData || SHA-256(client_data_json)`. Returns
/// JSON `{ authenticatorData, signature }` (Base64url, DER signature).
#[wasm_bindgen(js_name = passkeyAssert)]
pub fn passkey_assert(
    private_key: &str,
    rp_id: &str,
    client_data_json: &str,
    sign_count: u32,
) -> Result<String, JsValue> {
    let der = zeroize::Zeroizing::new(encoding::decode(private_key).map_err(js_error)?);
    let assertion = passkey::assert(
        &der,
        rp_id,
        client_data_json.as_bytes(),
        sign_count,
        Flags::SYNCED,
    )
    .map_err(js_error)?;
    Ok(serde_json::json!({
        "authenticatorData": encoding::encode(&assertion.authenticator_data),
        "signature": encoding::encode(&assertion.signature),
    })
    .to_string())
}

// --- Keys ---------------------------------------------------------------------

/// Keys derived from the master password and the Secret Key.
#[wasm_bindgen]
pub struct MasterKeys(CoreMasterKeys);

#[wasm_bindgen]
impl MasterKeys {
    /// Runs Argon2id and derives the master keys. This takes a moment; run it
    /// in a worker or show progress. Throws if the parameters are below the
    /// minimum or the Secret Key is malformed.
    pub fn derive(
        password: &str,
        secret_key: &str,
        account_id: &str,
        kdf_salt: &str,
        kdf_params_json: &str,
    ) -> Result<MasterKeys, JsValue> {
        let secret_key = SecretKey::parse(secret_key).map_err(js_error)?;
        let salt: [u8; kdf::SALT_LEN] = encoding::decode(kdf_salt)
            .map_err(js_error)?
            .try_into()
            .map_err(|_| JsValue::from(js_sys::Error::new("KDF salt must be 16 bytes")))?;
        let params: KdfParams = serde_json::from_str(kdf_params_json).map_err(json_error)?;
        kdf::derive_master_keys(password, &secret_key, account_id, &salt, params)
            .map(MasterKeys)
            .map_err(js_error)
    }
}

// --- OPAQUE -------------------------------------------------------------------

/// Client side of an account registration.
#[wasm_bindgen]
pub struct RegistrationFlow {
    flow: Option<ClientRegistrationFlow>,
    request: String,
}

#[wasm_bindgen]
impl RegistrationFlow {
    pub fn start(keys: &MasterKeys) -> Result<RegistrationFlow, JsValue> {
        let (flow, request) =
            ClientRegistrationFlow::start(&*keys.0.auth_secret).map_err(js_error)?;
        Ok(Self {
            flow: Some(flow),
            request: encoding::encode(&request),
        })
    }

    /// The registration request for the server (Base64url).
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    /// Processes the server's response and returns the upload message (Base64url).
    pub fn finish(&mut self, response: &str) -> Result<String, JsValue> {
        let flow = self
            .flow
            .take()
            .ok_or_else(|| JsValue::from(js_sys::Error::new("registration already finished")))?;
        let upload = flow
            .finish(&encoding::decode(response).map_err(js_error)?)
            .map_err(js_error)?;
        Ok(encoding::encode(&upload))
    }
}

/// Client side of a login.
#[wasm_bindgen]
pub struct LoginFlow {
    flow: Option<ClientLoginFlow>,
    request: String,
}

#[wasm_bindgen]
impl LoginFlow {
    pub fn start(keys: &MasterKeys) -> Result<LoginFlow, JsValue> {
        let (flow, request) = ClientLoginFlow::start(&*keys.0.auth_secret).map_err(js_error)?;
        Ok(Self {
            flow: Some(flow),
            request: encoding::encode(&request),
        })
    }

    /// The credential request for the server (Base64url).
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> String {
        self.request.clone()
    }

    /// Processes the server's response and returns the finalization message
    /// (Base64url). Throws `InvalidCredentialsError` if the password or Secret
    /// Key is wrong.
    pub fn finish(&mut self, response: &str) -> Result<String, JsValue> {
        let flow = self
            .flow
            .take()
            .ok_or_else(|| JsValue::from(js_sys::Error::new("login already finished")))?;
        let result = flow
            .finish(&encoding::decode(response).map_err(js_error)?)
            .map_err(js_error)?;
        Ok(encoding::encode(&result.finalization))
    }
}

// --- Keyring ------------------------------------------------------------------

/// The unlocked key hierarchy of an account.
#[wasm_bindgen]
pub struct Keyring {
    inner: CoreKeyring,
    encrypted_account_key: Option<String>,
}

#[wasm_bindgen]
impl Keyring {
    /// Creates the keys of a new account. Read `encryptedAccountKey` afterwards
    /// to upload it.
    pub fn create(keys: &MasterKeys, account_id: &str) -> Result<Keyring, JsValue> {
        let (inner, encrypted) = CoreKeyring::create(&keys.0.auk, account_id).map_err(js_error)?;
        Ok(Self {
            inner,
            encrypted_account_key: Some(encrypted),
        })
    }

    /// Unlocks an existing account. Throws `InvalidCredentialsError` if the
    /// master keys do not match.
    pub fn unlock(
        keys: &MasterKeys,
        account_id: &str,
        encrypted_account_key: &str,
    ) -> Result<Keyring, JsValue> {
        let inner = CoreKeyring::unlock(&keys.0.auk, account_id, encrypted_account_key)
            .map_err(js_error)?;
        Ok(Self {
            inner,
            encrypted_account_key: Some(encrypted_account_key.to_owned()),
        })
    }

    /// Restores a keyring exported with `exportSession`. Throws if the session
    /// key, account ID or blob do not match.
    #[wasm_bindgen(js_name = importSession)]
    pub fn import_session(
        session_key: &str,
        account_id: &str,
        blob: &str,
    ) -> Result<Keyring, JsValue> {
        let bytes = zeroize::Zeroizing::new(encoding::decode(session_key).map_err(js_error)?);
        let key: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| JsValue::from(js_sys::Error::new("session key must be 32 bytes")))?;
        let inner = CoreKeyring::import_session(&SymmetricKey::from_bytes(key), account_id, blob)
            .map_err(js_error)?;
        Ok(Self {
            inner,
            encrypted_account_key: None,
        })
    }

    /// Exports the unlocked keys encrypted under a fresh session key. Returns
    /// JSON `{ sessionKey, blob }` (Base64url). Keep both in memory-only
    /// storage (for example `chrome.storage.session`) and delete them on lock.
    #[wasm_bindgen(js_name = exportSession)]
    pub fn export_session(&self) -> Result<String, JsValue> {
        let (key, blob) = self.inner.export_session().map_err(js_error)?;
        Ok(serde_json::json!({
            "sessionKey": encoding::encode(key.as_bytes()),
            "blob": blob,
        })
        .to_string())
    }

    /// Encrypts the account key with new master keys, for changing the master
    /// password. Returns Base64url.
    #[wasm_bindgen(js_name = wrapAccountKey)]
    pub fn wrap_account_key(&self, keys: &MasterKeys) -> Result<String, JsValue> {
        self.inner.wrap_account_key(&keys.0.auk).map_err(js_error)
    }

    /// The account key encrypted with the Account Unlock Key (Base64url).
    #[wasm_bindgen(getter, js_name = encryptedAccountKey)]
    pub fn encrypted_account_key(&self) -> Option<String> {
        self.encrypted_account_key.clone()
    }

    /// Creates a vault. Returns JSON `{ id, encryptedKey, encryptedMeta }`.
    #[wasm_bindgen(js_name = createVault)]
    pub fn create_vault(&mut self, meta_json: &str) -> Result<String, JsValue> {
        let vault = self.inner.create_vault(meta_json).map_err(js_error)?;
        Ok(serde_json::json!({
            "id": vault.id,
            "encryptedKey": vault.encrypted_key,
            "encryptedMeta": vault.encrypted_meta,
        })
        .to_string())
    }

    #[wasm_bindgen(js_name = addVault)]
    pub fn add_vault(&mut self, vault_id: &str, encrypted_key: &str) -> Result<(), JsValue> {
        self.inner
            .add_vault(vault_id, encrypted_key)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = hasVault)]
    pub fn has_vault(&self, vault_id: &str) -> bool {
        self.inner.has_vault(vault_id)
    }

    #[wasm_bindgen(js_name = encryptVaultMeta)]
    pub fn encrypt_vault_meta(&self, vault_id: &str, meta_json: &str) -> Result<String, JsValue> {
        self.inner
            .encrypt_vault_meta(vault_id, meta_json)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decryptVaultMeta)]
    pub fn decrypt_vault_meta(
        &self,
        vault_id: &str,
        encrypted_meta: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .decrypt_vault_meta(vault_id, encrypted_meta)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = encryptItem)]
    pub fn encrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision_: f64,
        data_json: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .encrypt_item(vault_id, item_id, revision(revision_)?, data_json)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = decryptItem)]
    pub fn decrypt_item(
        &self,
        vault_id: &str,
        item_id: &str,
        revision_: f64,
        encrypted: &str,
    ) -> Result<String, JsValue> {
        self.inner
            .decrypt_item(vault_id, item_id, revision(revision_)?, encrypted)
            .map_err(js_error)
    }
}
