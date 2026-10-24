//! Service accounts (wave F2): machine identities for CI, scripts and AI
//! agents, without a master password.
//!
//! A service account belongs to an account (its *owner*). It has its own
//! X-Wing key pair. The owner's client seals the keys of selected vaults to
//! it and signs each grant. The service account's token holds a 256-bit
//! secret that never reaches the server; two keys are derived from it:
//!
//! ```text
//! token      = "pbx_sa_" || id || "_" || base64url(secret)          (secret: 32 random bytes)
//! auth_key   = HKDF-SHA256(ikm = secret, info = "passbox/v1/sa-auth|{id}")   sent to the server
//! auth_hash  = hex(SHA-256(base64url(auth_key)))                            stored by the server
//! wrap_key   = HKDF-SHA256(ikm = secret, info = "passbox/v1/sa-wrap|{id}")   never leaves the client
//!
//! public     = canonical("passbox/v1/sa-public-key", id, owner_id, enc_pk, created_at)
//! public_sig = Ed25519(owner.sig_sk, public)
//! private    = XChaCha20-Poly1305(wrap_key,
//!                canonical("passbox/v1/sa-private", enc_seed, owner_id, owner_sig_pk),
//!                aad = "passbox/v1/sa-private|{id}")
//!
//! sealed     = Seal(enc_pk, vault_key, purpose = "sa-vault-key",
//!                   context = canonical("passbox/v1/sa-vault-key-context", id, vault_id, epoch))
//! grant      = canonical("passbox/v1/sa-vault-grant", id, key_hash(public), vault_id, epoch,
//!                        permission, sealed_hash, owner_id, granted_at)
//! grant_sig  = Ed25519(owner.sig_sk, grant)
//! ```
//!
//! The server authenticates the service account with `auth_key` (it only
//! stores its hash) and cannot derive `wrap_key` from it. The owner's
//! signing key travels inside `private`, which only the token holder can
//! decrypt, so the service account accepts vault keys only from its owner:
//! a server that sealed a key of its own choosing to the (public) service
//! account key would fail the grant signature check. The owner checks
//! `public_sig` before sealing more vault keys later, so the server cannot
//! swap the public key either.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::aead::SymmetricKey;
use crate::canon::{Reader, Writer};
use crate::identity::{self, EncryptionKey, HASH_LEN, SIG_PK_LEN, SIGNATURE_LEN};
use crate::keyring::{Keyring, item_aad, key_from_plaintext, vault_meta_aad};
use crate::{Error, Result, encoding, id, random};

const TOKEN_PREFIX: &str = "pbx_sa_";
const SECRET_LEN: usize = 32;
/// Length of the Base64url secret in a token.
const SECRET_ENCODED_LEN: usize = 43;
const PUBLIC_TAG: &str = "passbox/v1/sa-public-key";
const PRIVATE_TAG: &str = "passbox/v1/sa-private";
const GRANT_TAG: &str = "passbox/v1/sa-vault-grant";
const CONTEXT_TAG: &str = "passbox/v1/sa-vault-key-context";
const SEAL_PURPOSE: &str = "sa-vault-key";

/// What a service account may do with a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Read,
    /// Read and write.
    Write,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            _ => Err(Error::InvalidData(format!("unknown permission {value:?}"))),
        }
    }
}

/// A parsed service account token. The secret is wiped on drop.
pub struct Token {
    id: String,
    secret: Zeroizing<[u8; SECRET_LEN]>,
}

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Token")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

fn derive(secret: &[u8], info: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, secret)
        .expand(info.as_bytes(), &mut *okm)
        .map_err(|_| Error::Kdf("HKDF expand failed".into()))?;
    Ok(okm)
}

impl Token {
    fn generate(id: &str) -> Result<Self> {
        Ok(Self {
            id: id.to_owned(),
            secret: Zeroizing::new(random::bytes()?),
        })
    }

    /// Parses `pbx_sa_{id}_{secret}`. Surrounding whitespace is ignored.
    pub fn parse(token: &str) -> Result<Self> {
        let invalid = || Error::InvalidData("not a Passbox service account token".into());
        let rest = token.trim().strip_prefix(TOKEN_PREFIX).ok_or_else(invalid)?;
        if rest.len() != id::ID_LEN + 1 + SECRET_ENCODED_LEN || !rest.is_ascii() {
            return Err(invalid());
        }
        let (id, secret) = rest.split_at(id::ID_LEN);
        let secret = secret.strip_prefix('_').ok_or_else(invalid)?;
        if !id::is_valid_id(id) {
            return Err(invalid());
        }
        let bytes = Zeroizing::new(encoding::decode(secret).map_err(|_| invalid())?);
        let secret: [u8; SECRET_LEN] = bytes.as_slice().try_into().map_err(|_| invalid())?;
        Ok(Self {
            id: id.to_owned(),
            secret: Zeroizing::new(secret),
        })
    }

    /// Whether `value` looks like a service account token (prefix only).
    pub fn looks_like(value: &str) -> bool {
        value.trim().starts_with(TOKEN_PREFIX)
    }

    /// The service account ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The token in its display format. Treat it like a password.
    pub fn to_display_string(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{TOKEN_PREFIX}{}_{}",
            self.id,
            encoding::encode(&*self.secret)
        ))
    }

    /// The key the server authenticates the service account with (Base64url).
    pub fn auth_key(&self) -> Result<Zeroizing<String>> {
        let key = derive(&*self.secret, &format!("passbox/v1/sa-auth|{}", self.id))?;
        Ok(Zeroizing::new(encoding::encode(&*key)))
    }

    fn wrap_key(&self) -> Result<SymmetricKey> {
        let key = derive(&*self.secret, &format!("passbox/v1/sa-wrap|{}", self.id))?;
        Ok(SymmetricKey::from_bytes(*key))
    }
}

/// What the server stores to recognize an authentication key: lowercase hex
/// SHA-256 of the Base64url `auth_key`.
pub fn auth_hash(auth_key: &str) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(auth_key.as_bytes()))
}

fn private_aad(id: &str) -> Vec<u8> {
    format!("passbox/v1/sa-private|{id}").into_bytes()
}

/// The public key of a service account, as signed by its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub id: String,
    pub owner_id: String,
    pub enc_pk: Vec<u8>,
    /// Unix milliseconds.
    pub created_at: i64,
}

impl PublicKey {
    pub fn to_canonical(&self) -> Vec<u8> {
        Writer::new(PUBLIC_TAG)
            .str(&self.id)
            .str(&self.owner_id)
            .bytes(&self.enc_pk)
            .i64(self.created_at)
            .finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, PUBLIC_TAG)?;
        let key = Self {
            id: r.string()?,
            owner_id: r.string()?,
            enc_pk: r.bytes()?.to_vec(),
            created_at: r.i64()?,
        };
        r.finish()?;
        if key.enc_pk.len() != identity::ENC_PK_LEN || !id::is_valid_id(&key.id) {
            return Err(Error::InvalidData("invalid service account key".into()));
        }
        Ok(key)
    }

    /// Parses Base64url and checks the owner's signature.
    pub fn verify(encoded: &str, signature: &str, owner_sig_pk: &[u8; SIG_PK_LEN]) -> Result<Self> {
        let bytes = encoding::decode(encoded)?;
        identity::verify(owner_sig_pk, &bytes, &encoding::decode(signature)?)?;
        Self::from_canonical(&bytes)
    }
}

/// The hash grants refer to.
fn key_hash(canonical_public: &[u8]) -> [u8; HASH_LEN] {
    identity::object_hash(canonical_public)
}

fn seal_context(id: &str, vault_id: &str, epoch: u32) -> Vec<u8> {
    Writer::new(CONTEXT_TAG)
        .str(id)
        .str(vault_id)
        .u64(u64::from(epoch))
        .finish()
}

/// A vault key granted to a service account, signed by the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub service_account_id: String,
    pub key_hash: [u8; HASH_LEN],
    pub vault_id: String,
    pub key_epoch: u32,
    pub permission: Permission,
    pub sealed_hash: [u8; HASH_LEN],
    pub owner_id: String,
    /// Unix milliseconds.
    pub granted_at: i64,
}

impl Grant {
    pub fn to_canonical(&self) -> Vec<u8> {
        Writer::new(GRANT_TAG)
            .str(&self.service_account_id)
            .bytes(&self.key_hash)
            .str(&self.vault_id)
            .u64(u64::from(self.key_epoch))
            .str(self.permission.as_str())
            .bytes(&self.sealed_hash)
            .str(&self.owner_id)
            .i64(self.granted_at)
            .finish()
    }

    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, GRANT_TAG)?;
        let grant = Self {
            service_account_id: r.string()?,
            key_hash: r.array()?,
            vault_id: r.string()?,
            key_epoch: r.u32()?,
            permission: Permission::parse(r.str()?)?,
            sealed_hash: r.array()?,
            owner_id: r.string()?,
            granted_at: r.i64()?,
        };
        r.finish()?;
        Ok(grant)
    }
}

/// A new service account, ready for upload. `token` is shown to the user
/// once and never stored by Passbox.
pub struct NewServiceAccount {
    pub id: String,
    pub token: Zeroizing<String>,
    /// Base64url canonical [`PublicKey`].
    pub public_key: String,
    /// Owner's signature over `public_key`.
    pub public_key_signature: String,
    pub encrypted_private: String,
    pub auth_hash: String,
}

/// A sealed vault key for a service account, ready for upload. All
/// Base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantUpload {
    pub vault_id: String,
    pub key_epoch: u32,
    pub permission: Permission,
    pub sealed_key: String,
    pub grant: String,
    pub grant_signature: String,
}

impl Keyring {
    /// Creates a service account owned by this account: generates its key
    /// pair and token. Requires the account's key pairs.
    pub fn create_service_account(&self, created_at: i64) -> Result<NewServiceAccount> {
        let owner = self.account_keys()?;
        let sa_id = id::new_id()?;
        let token = Token::generate(&sa_id)?;
        let enc = EncryptionKey::generate()?;
        let public = PublicKey {
            id: sa_id.clone(),
            owner_id: self.account_id.clone(),
            enc_pk: enc.public_key(),
            created_at,
        }
        .to_canonical();
        let signature = owner.sig.sign(&public);
        let private = Zeroizing::new(
            Writer::new(PRIVATE_TAG)
                .bytes(enc.seed())
                .str(&self.account_id)
                .bytes(&owner.bundle.bundle.sig_pk)
                .finish(),
        );
        let encrypted = token.wrap_key()?.encrypt(&private, &private_aad(&sa_id))?;
        let auth_key = token.auth_key()?;
        Ok(NewServiceAccount {
            id: sa_id,
            token: token.to_display_string(),
            public_key: encoding::encode(&public),
            public_key_signature: encoding::encode(&signature),
            encrypted_private: encoding::encode(&encrypted),
            auth_hash: auth_hash(&auth_key),
        })
    }

    /// Seals the key of `vault_id` at `key_epoch` for a service account this
    /// account owns. Checks the owner's signature on the public key first,
    /// so a server cannot substitute a key of its own.
    pub fn grant_service_account(
        &self,
        public_key: &str,
        public_key_signature: &str,
        vault_id: &str,
        key_epoch: u32,
        permission: Permission,
        granted_at: i64,
    ) -> Result<GrantUpload> {
        let owner = self.account_keys()?;
        let key = PublicKey::verify(
            public_key,
            public_key_signature,
            &owner.bundle.bundle.sig_pk,
        )?;
        if key.owner_id != self.account_id {
            return Err(Error::InvalidData(
                "the service account belongs to another account".into(),
            ));
        }
        let canonical = encoding::decode(public_key)?;
        let key_hash = key_hash(&canonical);
        let vault_key = self.vault_key(vault_id, key_epoch)?;
        let sealed = identity::seal(
            &key.enc_pk,
            &key_hash,
            SEAL_PURPOSE,
            &seal_context(&key.id, vault_id, key_epoch),
            vault_key.as_bytes(),
        )?;
        let grant = Grant {
            service_account_id: key.id,
            key_hash,
            vault_id: vault_id.to_owned(),
            key_epoch,
            permission,
            sealed_hash: identity::sealed_hash(&sealed),
            owner_id: self.account_id.clone(),
            granted_at,
        }
        .to_canonical();
        Ok(GrantUpload {
            vault_id: vault_id.to_owned(),
            key_epoch,
            permission,
            sealed_key: encoding::encode(&sealed),
            grant: encoding::encode(&grant),
            grant_signature: encoding::encode(&owner.sig.sign(&grant)),
        })
    }
}

/// A vault key the service account opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedGrant {
    pub vault_id: String,
    pub key_epoch: u32,
    pub permission: Permission,
}

/// The unlocked keys of a service account: its private key, its owner's
/// signing key and the vault keys it was granted. Wiped on drop.
pub struct ServiceAccountKeyring {
    id: String,
    owner_id: String,
    owner_sig_pk: [u8; SIG_PK_LEN],
    enc: EncryptionKey,
    key_hash: [u8; HASH_LEN],
    vault_keys: std::collections::HashMap<(String, u32), SymmetricKey>,
}

impl core::fmt::Debug for ServiceAccountKeyring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServiceAccountKeyring")
            .field("id", &self.id)
            .field("vaults", &self.vault_keys.len())
            .finish_non_exhaustive()
    }
}

impl ServiceAccountKeyring {
    /// Decrypts the private key with the token and checks that it matches
    /// the public key. Fails with [`Error::InvalidCredentials`] for a token
    /// that does not belong to this service account.
    pub fn unlock(token: &Token, public_key: &str, encrypted_private: &str) -> Result<Self> {
        let plaintext = Zeroizing::new(
            token
                .wrap_key()?
                .decrypt(
                    &encoding::decode(encrypted_private)?,
                    &private_aad(&token.id),
                )
                .map_err(|_| Error::InvalidCredentials)?,
        );
        let mut r = Reader::new(&plaintext, PRIVATE_TAG)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(r.array()?);
        let owner_id = r.string()?;
        let owner_sig_pk: [u8; SIG_PK_LEN] = r.array()?;
        r.finish()?;
        let enc = EncryptionKey::from_seed(&seed);
        let canonical = encoding::decode(public_key)?;
        let public = PublicKey::from_canonical(&canonical)?;
        if public.id != token.id || public.owner_id != owner_id || public.enc_pk != enc.public_key()
        {
            return Err(Error::InvalidData(
                "the service account's public key does not match its private key".into(),
            ));
        }
        Ok(Self {
            id: token.id.clone(),
            owner_id,
            owner_sig_pk,
            enc,
            key_hash: key_hash(&canonical),
            vault_keys: std::collections::HashMap::new(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// The account that owns the service account and approves its agent
    /// requests.
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// The owner's signing key, from the encrypted private part (not from
    /// the server).
    pub fn owner_sig_pk(&self) -> &[u8; SIG_PK_LEN] {
        &self.owner_sig_pk
    }

    /// Verifies a grant against the owner's signature and opens the vault
    /// key it covers.
    pub fn open_grant(
        &mut self,
        sealed_key: &str,
        grant: &str,
        grant_signature: &str,
    ) -> Result<OpenedGrant> {
        let canonical = encoding::decode(grant)?;
        let signature = encoding::decode(grant_signature)?;
        if signature.len() != SIGNATURE_LEN {
            return Err(Error::InvalidSignature);
        }
        identity::verify(&self.owner_sig_pk, &canonical, &signature)?;
        let grant = Grant::from_canonical(&canonical)?;
        let sealed = encoding::decode(sealed_key)?;
        if grant.service_account_id != self.id
            || grant.owner_id != self.owner_id
            || grant.key_hash != self.key_hash
            || grant.sealed_hash != identity::sealed_hash(&sealed)
        {
            return Err(Error::InvalidData(
                "the vault grant does not match this service account".into(),
            ));
        }
        let key = self.enc.open(
            &self.key_hash,
            SEAL_PURPOSE,
            &seal_context(&self.id, &grant.vault_id, grant.key_epoch),
            &sealed,
        )?;
        self.vault_keys.insert(
            (grant.vault_id.clone(), grant.key_epoch),
            key_from_plaintext(key.to_vec())?,
        );
        Ok(OpenedGrant {
            vault_id: grant.vault_id,
            key_epoch: grant.key_epoch,
            permission: grant.permission,
        })
    }

    pub fn has_vault_key(&self, vault_id: &str, epoch: u32) -> bool {
        self.vault_keys.contains_key(&(vault_id.to_owned(), epoch))
    }

    fn vault_key(&self, vault_id: &str, epoch: u32) -> Result<&SymmetricKey> {
        self.vault_keys
            .get(&(vault_id.to_owned(), epoch))
            .ok_or_else(|| Error::MissingKey(format!("vault {vault_id} (key epoch {epoch})")))
    }

    pub fn decrypt_vault_meta_at(
        &self,
        vault_id: &str,
        epoch: u32,
        encrypted_meta: &str,
    ) -> Result<String> {
        let plaintext = self.vault_key(vault_id, epoch)?.decrypt(
            &encoding::decode(encrypted_meta)?,
            &vault_meta_aad(vault_id, epoch),
        )?;
        crate::keyring::into_json_string(plaintext)
    }

    pub fn decrypt_item_at(
        &self,
        vault_id: &str,
        epoch: u32,
        item_id: &str,
        revision: u64,
        encrypted: &str,
    ) -> Result<String> {
        let plaintext = self.vault_key(vault_id, epoch)?.decrypt(
            &encoding::decode(encrypted)?,
            &item_aad(vault_id, item_id, revision, epoch),
        )?;
        crate::keyring::into_json_string(plaintext)
    }

    pub fn encrypt_item_at(
        &self,
        vault_id: &str,
        epoch: u32,
        item_id: &str,
        revision: u64,
        data_json: &str,
    ) -> Result<String> {
        crate::keyring::ensure_json(data_json.as_bytes())?;
        let envelope = self.vault_key(vault_id, epoch)?.encrypt(
            data_json.as_bytes(),
            &item_aad(vault_id, item_id, revision, epoch),
        )?;
        Ok(encoding::encode(&envelope))
    }

    /// Verifies an agent decision signed by the owner (see [`crate::agent_grant`]).
    pub fn verify_agent_decision(
        &self,
        request: &[u8],
        decision: &str,
        signature: &str,
    ) -> Result<crate::agent_grant::Decision> {
        crate::agent_grant::verify_decision(
            &self.owner_sig_pk,
            &self.owner_id,
            request,
            decision,
            signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Keyring {
        let auk = SymmetricKey::generate().unwrap();
        let (mut keyring, _) = Keyring::create(&auk, &id::new_id().unwrap()).unwrap();
        keyring.create_account_keys(1).unwrap();
        keyring
    }

    #[test]
    fn token_round_trip() {
        let token = Token::generate(&id::new_id().unwrap()).unwrap();
        let text = token.to_display_string();
        assert!(text.starts_with("pbx_sa_"));
        assert!(Token::looks_like(&text));
        let parsed = Token::parse(&format!("  {}\n", text.as_str())).unwrap();
        assert_eq!(parsed.id(), token.id());
        assert_eq!(*parsed.auth_key().unwrap(), *token.auth_key().unwrap());
        assert!(Token::parse("pbx_sa_short").is_err());
        assert!(Token::parse(&text.replace("pbx_sa_", "pbx_xx_")).is_err());
        let mut broken = text.to_string();
        broken.replace_range(7..8, "u"); // 'u' is not in the ID alphabet
        assert!(Token::parse(&broken).is_err());
    }

    #[test]
    fn auth_and_wrap_keys_differ_and_depend_on_the_id() {
        let token = Token::generate(&id::new_id().unwrap()).unwrap();
        let other = Token {
            id: id::new_id().unwrap(),
            secret: token.secret.clone(),
        };
        assert_ne!(*token.auth_key().unwrap(), *other.auth_key().unwrap());
        assert_ne!(
            token.wrap_key().unwrap().as_bytes(),
            token.auth_key().unwrap().as_bytes()
        );
        assert_eq!(auth_hash("abc").len(), 64);
    }

    #[test]
    fn grant_and_open_vault_keys() {
        let mut owner = owner();
        let vault = owner.create_vault(r#"{"name":"CI"}"#).unwrap();
        let item = owner
            .encrypt_item(&vault.id, "item", 1, r#"{"title":"db"}"#)
            .unwrap();
        let sa = owner.create_service_account(5).unwrap();
        let grant = owner
            .grant_service_account(
                &sa.public_key,
                &sa.public_key_signature,
                &vault.id,
                0,
                Permission::Read,
                6,
            )
            .unwrap();

        let token = Token::parse(&sa.token).unwrap();
        assert_eq!(auth_hash(&token.auth_key().unwrap()), sa.auth_hash);
        let mut keyring =
            ServiceAccountKeyring::unlock(&token, &sa.public_key, &sa.encrypted_private).unwrap();
        assert_eq!(keyring.owner_id(), owner.account_id());
        let opened = keyring
            .open_grant(&grant.sealed_key, &grant.grant, &grant.grant_signature)
            .unwrap();
        assert_eq!(opened.permission, Permission::Read);
        assert_eq!(
            keyring.decrypt_item_at(&vault.id, 0, "item", 1, &item).unwrap(),
            r#"{"title":"db"}"#
        );
        assert_eq!(
            keyring
                .decrypt_vault_meta_at(&vault.id, 0, &vault.encrypted_meta)
                .unwrap(),
            r#"{"name":"CI"}"#
        );
        let written = keyring
            .encrypt_item_at(&vault.id, 0, "new", 1, r#"{"title":"x"}"#)
            .unwrap();
        assert_eq!(
            owner.decrypt_item(&vault.id, "new", 1, &written).unwrap(),
            r#"{"title":"x"}"#
        );
    }

    #[test]
    fn rejects_wrong_tokens_and_foreign_grants() {
        let mut owner = owner();
        let vault = owner.create_vault(r#"{"name":"CI"}"#).unwrap();
        let sa = owner.create_service_account(5).unwrap();
        let other = owner.create_service_account(5).unwrap();

        // Another service account's token does not open this one.
        let wrong = Token::parse(&other.token).unwrap();
        assert_eq!(
            ServiceAccountKeyring::unlock(&wrong, &sa.public_key, &sa.encrypted_private)
                .unwrap_err(),
            Error::InvalidCredentials
        );
        // A swapped public key is refused.
        let token = Token::parse(&sa.token).unwrap();
        assert!(
            ServiceAccountKeyring::unlock(&token, &other.public_key, &sa.encrypted_private)
                .is_err()
        );

        let mut keyring =
            ServiceAccountKeyring::unlock(&token, &sa.public_key, &sa.encrypted_private).unwrap();
        // A grant for the other service account does not open here.
        let foreign = owner
            .grant_service_account(
                &other.public_key,
                &other.public_key_signature,
                &vault.id,
                0,
                Permission::Write,
                1,
            )
            .unwrap();
        assert!(
            keyring
                .open_grant(
                    &foreign.sealed_key,
                    &foreign.grant,
                    &foreign.grant_signature
                )
                .is_err()
        );

        // A key sealed by someone other than the owner (for example the
        // server) has no valid owner signature.
        let mallory = self::owner();
        let mut mallory = mallory;
        let fake_vault = mallory.create_vault(r#"{"name":"fake"}"#).unwrap();
        let public = PublicKey::from_canonical(&encoding::decode(&sa.public_key).unwrap()).unwrap();
        let canonical = encoding::decode(&sa.public_key).unwrap();
        let sealed = identity::seal(
            &public.enc_pk,
            &key_hash(&canonical),
            SEAL_PURPOSE,
            &seal_context(&public.id, &fake_vault.id, 0),
            mallory.vault_key(&fake_vault.id, 0).unwrap().as_bytes(),
        )
        .unwrap();
        let grant = Grant {
            service_account_id: public.id.clone(),
            key_hash: key_hash(&canonical),
            vault_id: fake_vault.id.clone(),
            key_epoch: 0,
            permission: Permission::Read,
            sealed_hash: identity::sealed_hash(&sealed),
            owner_id: owner.account_id().to_owned(),
            granted_at: 1,
        }
        .to_canonical();
        let signature = mallory.account_keys().unwrap().sig.sign(&grant);
        assert_eq!(
            keyring
                .open_grant(
                    &encoding::encode(&sealed),
                    &encoding::encode(&grant),
                    &encoding::encode(&signature)
                )
                .unwrap_err(),
            Error::InvalidSignature
        );

        // The owner refuses to seal to a public key it did not sign.
        assert!(
            owner
                .grant_service_account(
                    &sa.public_key,
                    &other.public_key_signature,
                    &vault.id,
                    0,
                    Permission::Read,
                    1
                )
                .is_err()
        );
    }

    #[test]
    fn tampered_sealed_keys_are_refused() {
        let mut owner = owner();
        let vault = owner.create_vault(r#"{"name":"CI"}"#).unwrap();
        let sa = owner.create_service_account(5).unwrap();
        let grant = owner
            .grant_service_account(
                &sa.public_key,
                &sa.public_key_signature,
                &vault.id,
                0,
                Permission::Read,
                6,
            )
            .unwrap();
        let other = owner
            .grant_service_account(
                &sa.public_key,
                &sa.public_key_signature,
                &vault.id,
                0,
                Permission::Read,
                6,
            )
            .unwrap();
        let token = Token::parse(&sa.token).unwrap();
        let mut keyring =
            ServiceAccountKeyring::unlock(&token, &sa.public_key, &sa.encrypted_private).unwrap();
        // Sealed bytes of another grant do not match this grant's hash.
        assert!(
            keyring
                .open_grant(&other.sealed_key, &grant.grant, &grant.grant_signature)
                .is_err()
        );
    }
}
