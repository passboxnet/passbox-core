//! Organizations, invitations, groups and shared vaults.
//!
//! All cryptography (sealing, signing, verification) happens in
//! `passbox_core::sharing`; these methods add the HTTP calls and the
//! multi-step flows (confirming a member, removing a member with key
//! rotation, re-encrypting a vault). See `docs/architecture/sharing.md`.

use passbox_core::directory::LookupResponse;
use passbox_core::sharing::objects::{OrgKind, OrgRole, PrincipalType, VaultRole};
use passbox_core::sharing::state::{
    DirectoryLookup, GroupView, OrgView, SharedVaultView, SharingView, Warning,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Client, now_ms};
use crate::{Error, Result};

/// Items per re-encryption request.
const REENCRYPT_BATCH: usize = 100;

/// A new invitation. The token is shown once; the server only keeps its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invitation {
    pub id: String,
    pub token: String,
    /// `{server}/invite/{token}#org={fingerprint}`. The fragment lets the
    /// invitee check the organization's identity; pass the link on through a
    /// channel you trust.
    pub link: String,
    pub expires_at: i64,
}

/// A pending invitation (`GET /orgs/{id}/invitations`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationInfo {
    pub id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// What an invitation link is for (`GET /invitations/{token}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationPreview {
    pub org_id: String,
    pub org_kind: String,
    pub email: String,
    pub role: String,
    pub expires_at: i64,
    /// Email of the admin who invited; missing from older servers.
    #[serde(default)]
    pub inviter_email: Option<String>,
    /// The organization's admins will be able to restore this account's
    /// access once it joined (recovery on and required; never for guests).
    #[serde(default)]
    pub recovery: bool,
}

/// Who owns a vault and what this account may do with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultAccess {
    pub vault_id: String,
    /// `None` for personal vaults.
    pub org_id: Option<String>,
    /// `manage` for personal vaults; for shared vaults the verified role.
    pub role: Option<String>,
    pub verified: bool,
}

/// Splits an invitation link (or a bare token) into token and organization
/// fingerprint.
pub fn parse_invitation_link(link: &str) -> (String, Option<String>) {
    let (path, fragment) = match link.split_once('#') {
        Some((path, fragment)) => (path, Some(fragment)),
        None => (link, None),
    };
    let token = path
        .rsplit_once("/invite/")
        .map_or(path, |(_, token)| token)
        .trim_matches('/')
        .to_owned();
    let root = fragment.and_then(|f| {
        f.split('&')
            .find_map(|part| part.strip_prefix("org="))
            .map(str::to_owned)
    });
    (token, root)
}

impl Client {
    pub(super) fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        self.with_token(|token| self.api.request(method, path, token, body.clone()))
    }

    pub(super) fn with_keyring<T>(
        &self,
        f: impl FnOnce(&mut passbox_core::keyring::Keyring) -> passbox_core::Result<T>,
    ) -> Result<T> {
        let mut guard = self.lock_session();
        let session = guard.as_mut().ok_or(Error::Locked)?;
        Ok(f(&mut session.keyring)?)
    }

    fn view(&self) -> Result<SharingView> {
        let guard = self.lock_session();
        Ok(guard
            .as_ref()
            .ok_or(Error::Locked)?
            .keyring
            .sharing_view()
            .clone())
    }

    // --- State ---------------------------------------------------------------------

    /// Organizations this account belongs to, with verified members and
    /// groups.
    pub fn orgs(&self) -> Result<Vec<OrgView>> {
        Ok(self.view()?.orgs)
    }

    pub fn org(&self, org_id: &str) -> Result<OrgView> {
        self.orgs()?
            .into_iter()
            .find(|o| o.id == org_id)
            .ok_or_else(|| Error::NotFound(org_id.to_owned()))
    }

    /// Shared vaults this account can open, with their verified members.
    pub fn shared_vaults(&self) -> Result<Vec<SharedVaultView>> {
        Ok(self.view()?.vaults)
    }

    /// Problems found while verifying sharing data, for example a member's
    /// key that changed (`key_changed`).
    pub fn sharing_warnings(&self) -> Result<Vec<Warning>> {
        Ok(self.view()?.warnings)
    }

    /// Ownership and this account's role for a vault.
    pub fn vault_access(&self, vault_id: &str) -> Result<VaultAccess> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        let vault = session.vaults.get(vault_id).cloned();
        let shared = session
            .keyring
            .sharing_view()
            .vaults
            .iter()
            .find(|v| v.vault_id == vault_id)
            .cloned();
        match (vault, shared) {
            (_, Some(shared)) => Ok(VaultAccess {
                vault_id: vault_id.to_owned(),
                org_id: Some(shared.org_id),
                role: shared.role,
                verified: shared.verified,
            }),
            (Some(vault), None) if vault.org_id.is_none() => Ok(VaultAccess {
                vault_id: vault_id.to_owned(),
                org_id: None,
                role: Some("manage".into()),
                verified: true,
            }),
            _ => Err(Error::NotFound(vault_id.to_owned())),
        }
    }

    /// Fingerprint of this account's own keys, for comparing with others.
    pub fn own_fingerprint(&self) -> Result<String> {
        let guard = self.lock_session();
        guard
            .as_ref()
            .ok_or(Error::Locked)?
            .keyring
            .own_bundle()
            .map(|b| b.fingerprint())
            .ok_or_else(|| Error::InvalidData("the account has no key pairs yet".into()))
    }

    /// Looks up an account's key in the key directory and verifies the
    /// proof. New keys are pinned; a changed key is reported (`status:
    /// "changed"`) and must be accepted with [`Client::accept_key_change`].
    pub fn lookup_key(&self, account_id: &str) -> Result<DirectoryLookup> {
        let since = {
            let guard = self.lock_session();
            guard
                .as_ref()
                .ok_or(Error::Locked)?
                .keyring
                .trust_store()
                .directory
                .size
        };
        let response: LookupResponse = serde_json::from_value(self.call(
            "GET",
            &format!("/api/v1/keys/{account_id}?since={since}"),
            None,
        )?)?;
        let lookup = self.with_keyring(|k| k.verify_directory_lookup(account_id, &response))?;
        self.save_trust()?;
        Ok(lookup)
    }

    /// Checks that the key directory lists this account's own key (detects
    /// a server publishing another key for it).
    pub fn verify_own_key(&self) -> Result<DirectoryLookup> {
        let own = self.device_account()?.ok_or(Error::NoAccount)?.account_id;
        self.lookup_key(&own)
    }

    /// Trusts the current key of `account_id` after a change. Returns its
    /// fingerprint.
    pub fn accept_key_change(&self, account_id: &str) -> Result<String> {
        let fingerprint = self.with_keyring(|k| k.accept_key_change(account_id))?;
        self.save_trust()?;
        Ok(fingerprint)
    }

    fn save_trust(&self) -> Result<()> {
        let guard = self.lock_session();
        let session = guard.as_ref().ok_or(Error::Locked)?;
        self.store.put(
            crate::store::TRUST_KEY,
            &serde_json::to_vec(session.keyring.trust_store())?,
        )
    }

    // --- Organizations ---------------------------------------------------------------

    /// Creates a family organization with its shared family vault. Returns
    /// the organization ID.
    pub fn create_family(&self, name: &str, vault_name: &str) -> Result<String> {
        self.create_org(OrgKind::Family, name, Some(vault_name))
    }

    /// Creates a team organization. Returns its ID.
    pub fn create_team(&self, name: &str) -> Result<String> {
        self.create_org(OrgKind::Team, name, None)
    }

    fn create_org(&self, kind: OrgKind, name: &str, vault_name: Option<&str>) -> Result<String> {
        self.sync()?;
        let meta = json!({ "name": name }).to_string();
        let vault_meta = vault_name.map(|n| json!({ "name": n }).to_string());
        let request =
            self.with_keyring(|k| k.create_org(kind, &meta, vault_meta.as_deref(), now_ms()))?;
        let id = request.id.clone();
        self.call(
            "POST",
            "/api/v1/orgs",
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()?;
        self.set_up_new_org(&id)?;
        Ok(id)
    }

    /// Organization recovery is on by default (C1, since 25.10.2026): a new
    /// organization gets its recovery key and a first policy that requires
    /// enrollment ([`PolicyRules::new_org_defaults`]), and the creator
    /// enrolls. Admins can turn both off later.
    ///
    /// [`PolicyRules::new_org_defaults`]: passbox_core::policy::PolicyRules::new_org_defaults
    fn set_up_new_org(&self, org_id: &str) -> Result<()> {
        self.set_up_org_recovery(org_id)?;
        self.set_org_policy(
            org_id,
            &passbox_core::policy::PolicyRules::new_org_defaults(),
        )?;
        self.enroll_org_recovery(org_id)?;
        Ok(())
    }

    /// Renames an organization (admins).
    pub fn rename_org(&self, org_id: &str, name: &str) -> Result<()> {
        let (revision, epoch) = {
            let guard = self.lock_session();
            let session = guard.as_ref().ok_or(Error::Locked)?;
            let org = session
                .keyring
                .sharing_data()
                .orgs
                .get(org_id)
                .ok_or_else(|| Error::NotFound(org_id.to_owned()))?;
            (org.revision, org.meta_epoch)
        };
        let meta = json!({ "name": name }).to_string();
        let encrypted = self.with_keyring(|k| k.encrypt_org_meta(org_id, epoch, &meta))?;
        self.call(
            "PUT",
            &format!("/api/v1/orgs/{org_id}"),
            Some(
                json!({ "revision": revision + 1, "metaEpoch": epoch, "encryptedMeta": encrypted }),
            ),
        )?;
        self.sync()
    }

    /// Deletes an organization with all its vaults (owner only).
    pub fn delete_org(&self, org_id: &str) -> Result<()> {
        self.call("DELETE", &format!("/api/v1/orgs/{org_id}"), None)?;
        self.sync()
    }

    /// Invites someone by email with `role` (`admin`, `member` or `guest`).
    /// The server queues an invitation mail if a mailer is configured;
    /// the returned link can always be passed on directly.
    pub fn invite(&self, org_id: &str, email: &str, role: &str) -> Result<Invitation> {
        let (root, _) = self.with_keyring(|k| k.org_fingerprint(org_id))?;
        let fragment = format!("org={root}");
        let response = self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/invitations"),
            Some(json!({ "email": email, "role": role, "linkFragment": fragment })),
        )?;
        let token = response["token"].as_str().unwrap_or_default().to_owned();
        let path = response["path"].as_str().unwrap_or_default();
        Ok(Invitation {
            id: response["id"].as_str().unwrap_or_default().to_owned(),
            link: format!("{}{path}#{fragment}", self.api.base_url()),
            token,
            expires_at: response["expiresAt"].as_i64().unwrap_or_default(),
        })
    }

    /// Pending invitations of an organization (admins).
    pub fn invitations(&self, org_id: &str) -> Result<Vec<InvitationInfo>> {
        Ok(serde_json::from_value(self.call(
            "GET",
            &format!("/api/v1/orgs/{org_id}/invitations"),
            None,
        )?)?)
    }

    pub fn revoke_invitation(&self, org_id: &str, invitation_id: &str) -> Result<()> {
        self.call(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/invitations/{invitation_id}"),
            None,
        )?;
        Ok(())
    }

    /// What an invitation link (or token) is for. Works without signing in.
    pub fn preview_invitation(&self, link: &str) -> Result<InvitationPreview> {
        let (token, _) = parse_invitation_link(link);
        Ok(serde_json::from_value(
            self.api.invitation_preview(&token)?,
        )?)
    }

    /// Accepts an invitation link (or token) for the signed-in account and
    /// returns the organization ID. The membership stays `accepted` until
    /// an admin confirms it. The organization fingerprint in the link is
    /// pinned, so a server cannot substitute another organization.
    pub fn accept_invitation(&self, link: &str) -> Result<String> {
        let (token, root) = parse_invitation_link(link);
        // Publishes key pairs if needed: accepting requires them.
        self.sync()?;
        let preview: InvitationPreview =
            serde_json::from_value(self.api.invitation_preview(&token)?)?;
        if let Some(root) = root {
            self.with_keyring(|k| k.pin_org_root(&preview.org_id, &root))?;
            self.save_trust()?;
        }
        let response = self.call(
            "POST",
            "/api/v1/invitations/accept",
            Some(json!({ "token": token })),
        )?;
        self.sync()?;
        Ok(response["orgId"]
            .as_str()
            .unwrap_or(&preview.org_id)
            .to_owned())
    }

    /// Confirms a member who accepted an invitation (admins): looks up their
    /// key in the key directory, attests it and seals the organization key.
    /// In a family, the member (not a guest) also gets the family vault (edit). Returns
    /// the attested key's fingerprint, which admin and member can compare.
    pub fn confirm_member(&self, org_id: &str, account_id: &str) -> Result<String> {
        self.sync()?;
        let lookup = self.lookup_key(account_id)?;
        if lookup.status == "changed" {
            return Err(Error::Core(passbox_core::Error::KeyChanged(
                account_id.to_owned(),
            )));
        }
        let request = self.with_keyring(|k| k.confirm_member(org_id, account_id, now_ms()))?;
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{account_id}/confirm"),
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()?;
        let org = self.org(org_id)?;
        // Guests only see what is shared with them (B8): no family vault.
        let guest = org
            .members
            .iter()
            .any(|m| m.account_id == account_id && m.role == "guest");
        if org.kind == "family"
            && !guest
            && let Some(vault_id) = org.default_vault_id
        {
            let can_manage = self
                .shared_vaults()?
                .iter()
                .any(|v| v.vault_id == vault_id && v.role.as_deref() == Some("manage"));
            if can_manage {
                self.share_vault(&vault_id, "account", account_id, "edit")?;
            }
        }
        Ok(request.fingerprint)
    }

    /// Changes a member's role (admins; admin rights only by the owner).
    pub fn set_member_role(&self, org_id: &str, account_id: &str, role: &str) -> Result<()> {
        let role = OrgRole::parse(role)?;
        let request =
            self.with_keyring(|k| k.set_member_role(org_id, account_id, role, now_ms()))?;
        self.call(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/members/{account_id}"),
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()
    }

    /// Blocks a member from the organization's vaults on the server. This is
    /// not cryptographic; use [`Client::remove_member`] to rotate keys.
    pub fn suspend_member(&self, org_id: &str, account_id: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{account_id}/suspend"),
            Some(json!({})),
        )?;
        self.sync()
    }

    pub fn reactivate_member(&self, org_id: &str, account_id: &str) -> Result<()> {
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/members/{account_id}/reactivate"),
            Some(json!({})),
        )?;
        self.sync()
    }

    /// Removes a member and rotates every key they had: their groups, the
    /// vaults they could open (items are re-encrypted) and the organization
    /// key; members they attested are re-attested. Vaults this account
    /// cannot manage stay marked `rotation_pending` for their managers.
    pub fn remove_member(&self, org_id: &str, account_id: &str) -> Result<()> {
        // Re-attestations are prepared while the removed member's own
        // attestation still verifies.
        self.sync()?;
        let attestations =
            self.with_keyring(|k| k.reattest_members(org_id, account_id, now_ms()))?;
        let removed = self.call(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/members/{account_id}"),
            None,
        )?;
        self.sync()?;
        let groups: Vec<String> =
            serde_json::from_value(removed["groups"].clone()).unwrap_or_default();
        for group_id in groups {
            let is_member = self
                .org(org_id)?
                .groups
                .iter()
                .any(|g| g.id == group_id && g.is_member);
            if is_member {
                self.rotate_group(org_id, &group_id, &[account_id.to_owned()])?;
            }
        }
        self.sync()?;
        self.rotate_pending_vaults(org_id, &[(PrincipalType::Account, account_id.to_owned())])?;
        for attestation in attestations {
            self.call(
                "PUT",
                &format!("/api/v1/orgs/{org_id}/members/{}", attestation.account_id),
                Some(serde_json::to_value(&attestation)?),
            )?;
        }
        self.sync()?;
        let rotation = self.with_keyring(|k| k.rotate_org_key(org_id, now_ms()))?;
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/rotate-key"),
            Some(serde_json::to_value(&rotation)?),
        )?;
        self.sync()
    }

    /// Leaves an organization (not possible for its owner).
    pub fn leave_org(&self, org_id: &str) -> Result<()> {
        let own = self.device_account()?.ok_or(Error::NoAccount)?.account_id;
        self.call(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/members/{own}"),
            None,
        )?;
        self.sync()
    }

    // --- Shared vaults --------------------------------------------------------------------

    /// Creates a shared vault in an organization (owners and admins) and
    /// returns its ID. The creator manages it.
    pub fn create_shared_vault(&self, org_id: &str, name: &str) -> Result<String> {
        let meta = json!({ "name": name }).to_string();
        let request = self.with_keyring(|k| k.create_shared_vault(org_id, &meta, now_ms()))?;
        let id = request.id.clone();
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/vaults"),
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()?;
        Ok(id)
    }

    /// Shares a vault with an account or group (`principal_type` `account`
    /// or `group`) with `role` (`view`, `edit` or `manage`), or changes the
    /// role of an existing member. Refused while the member's key changed
    /// and the change was not accepted.
    pub fn share_vault(
        &self,
        vault_id: &str,
        principal_type: &str,
        principal_id: &str,
        role: &str,
    ) -> Result<()> {
        let principal_type = PrincipalType::parse(principal_type)?;
        let role = VaultRole::parse(role)?;
        let request = self.with_keyring(|k| {
            k.share_vault(vault_id, principal_type, principal_id, role, now_ms())
        })?;
        self.call(
            "POST",
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()
    }

    /// Removes a member from a vault. The vault key is rotated and every
    /// item re-encrypted, so the former member cannot read anything added
    /// later (they may have kept what they saw before).
    pub fn unshare_vault(
        &self,
        vault_id: &str,
        principal_type: &str,
        principal_id: &str,
    ) -> Result<()> {
        let principal_type = PrincipalType::parse(principal_type)?;
        self.rotate_vault_key(vault_id, &[(principal_type, principal_id.to_owned())])
    }

    /// The verified members of a shared vault.
    pub fn vault_members(&self, vault_id: &str) -> Result<SharedVaultView> {
        self.shared_vaults()?
            .into_iter()
            .find(|v| v.vault_id == vault_id)
            .ok_or_else(|| Error::NotFound(vault_id.to_owned()))
    }

    /// Rotates the vaults of an organization that are marked for rotation
    /// and that this account manages.
    pub fn rotate_pending_vaults(
        &self,
        org_id: &str,
        removed: &[(PrincipalType, String)],
    ) -> Result<()> {
        let pending: Vec<String> = self
            .shared_vaults()?
            .into_iter()
            .filter(|v| v.org_id == org_id && v.rotation_pending && v.has_key)
            .filter(|v| v.role.as_deref() == Some("manage"))
            .map(|v| v.vault_id)
            .collect();
        for vault_id in pending {
            self.rotate_vault_key(&vault_id, removed)?;
        }
        Ok(())
    }

    /// Rotates a vault's key (without `removed`) and re-encrypts its items.
    pub fn rotate_vault_key(
        &self,
        vault_id: &str,
        removed: &[(PrincipalType, String)],
    ) -> Result<()> {
        self.sync()?;
        let name = self
            .vaults()?
            .into_iter()
            .find(|v| v.id == vault_id)
            .map(|v| v.name)
            .ok_or_else(|| Error::NotFound(vault_id.to_owned()))?;
        let meta = json!({ "name": name }).to_string();
        let request = self.with_keyring(|k| k.rotate_vault(vault_id, removed, &meta, now_ms()))?;
        let epoch = request.key_epoch;
        self.call(
            "POST",
            &format!("/api/v1/vaults/{vault_id}/rotate"),
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()?;
        self.reencrypt_vault(vault_id, epoch)
    }

    /// Re-encrypts every item of a vault that is still at an older key
    /// epoch, in batches. Items changed meanwhile are retried once.
    pub fn reencrypt_vault(&self, vault_id: &str, epoch: u32) -> Result<()> {
        for _attempt in 0..2 {
            let batches: Vec<Vec<Value>> = {
                let guard = self.lock_session();
                let session = guard.as_ref().ok_or(Error::Locked)?;
                let items: Vec<Value> = session
                    .items
                    .values()
                    .filter(|i| i.vault_id == vault_id && i.key_epoch < epoch)
                    .map(|item| {
                        let json = serde_json::to_string(&item.data)?;
                        let encrypted = session.keyring.encrypt_item_at(
                            vault_id,
                            epoch,
                            &item.id,
                            item.revision + 1,
                            &json,
                        )?;
                        Ok(json!({
                            "id": item.id,
                            "revision": item.revision + 1,
                            "keyEpoch": epoch,
                            "encryptedData": encrypted,
                        }))
                    })
                    .collect::<Result<_>>()?;
                items
                    .chunks(REENCRYPT_BATCH)
                    .map(<[Value]>::to_vec)
                    .collect()
            };
            if batches.is_empty() {
                return Ok(());
            }
            for batch in batches {
                self.call(
                    "POST",
                    &format!("/api/v1/vaults/{vault_id}/items/batch"),
                    Some(json!({ "items": batch })),
                )?;
            }
            self.sync()?;
        }
        Ok(())
    }

    // --- Groups ------------------------------------------------------------------------------

    /// Groups of an organization.
    pub fn groups(&self, org_id: &str) -> Result<Vec<GroupView>> {
        Ok(self.org(org_id)?.groups)
    }

    /// Creates a group (admins) with the given members; the creator is
    /// always a member. Returns the group ID.
    pub fn create_group(&self, org_id: &str, name: &str, members: &[String]) -> Result<String> {
        let meta = json!({ "name": name }).to_string();
        let request = self.with_keyring(|k| k.create_group(org_id, &meta, members, now_ms()))?;
        let id = request.id.clone();
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/groups"),
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()?;
        Ok(id)
    }

    pub fn rename_group(&self, org_id: &str, group_id: &str, name: &str) -> Result<()> {
        let epoch = {
            let guard = self.lock_session();
            let session = guard.as_ref().ok_or(Error::Locked)?;
            session
                .keyring
                .sharing_data()
                .orgs
                .get(org_id)
                .map(|o| o.meta_epoch)
                .ok_or_else(|| Error::NotFound(org_id.to_owned()))?
        };
        let meta = json!({ "name": name }).to_string();
        let encrypted =
            self.with_keyring(|k| k.encrypt_group_meta(org_id, group_id, epoch, &meta))?;
        self.call(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/groups/{group_id}"),
            Some(json!({ "metaEpoch": epoch, "encryptedMeta": encrypted })),
        )?;
        self.sync()
    }

    /// Deletes a group (admins). Unshare its vaults first.
    pub fn delete_group(&self, org_id: &str, group_id: &str) -> Result<()> {
        self.call(
            "DELETE",
            &format!("/api/v1/orgs/{org_id}/groups/{group_id}"),
            None,
        )?;
        self.sync()
    }

    /// Adds a member to a group: one sealing of the group key.
    pub fn add_group_member(&self, org_id: &str, group_id: &str, account_id: &str) -> Result<()> {
        let request = self.with_keyring(|k| k.add_group_member(group_id, account_id, now_ms()))?;
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/groups/{group_id}/members"),
            Some(serde_json::to_value(&request)?),
        )?;
        self.sync()
    }

    /// Removes a member from a group: rotates the group key and the keys of
    /// the vaults shared with the group.
    pub fn remove_group_member(
        &self,
        org_id: &str,
        group_id: &str,
        account_id: &str,
    ) -> Result<()> {
        self.rotate_group(org_id, group_id, &[account_id.to_owned()])?;
        self.sync()?;
        self.rotate_pending_vaults(org_id, &[])
    }

    fn rotate_group(&self, org_id: &str, group_id: &str, removed: &[String]) -> Result<()> {
        let request = self.with_keyring(|k| k.rotate_group(group_id, removed, now_ms()))?;
        self.call(
            "POST",
            &format!("/api/v1/orgs/{org_id}/groups/{group_id}/rotate"),
            Some(serde_json::to_value(&request)?),
        )?;
        Ok(())
    }
}

// --- Policies (wave D2) -------------------------------------------------------------

impl Client {
    /// The policies in force per organization (verified in sync, or pinned
    /// when the server's copy is missing, older or invalid).
    pub fn org_policies(&self) -> Result<Vec<passbox_core::policy::OrgPolicyView>> {
        Ok(self.view()?.policies)
    }

    /// The combination of every policy this account is bound by. Clients
    /// enforce it: two-factor sign-in, master password strength, auto-lock
    /// limit, export, sharing outside the organization, personal vaults.
    pub fn effective_policy(&self) -> Result<passbox_core::policy::EffectivePolicy> {
        Ok(self.view()?.effective_policy)
    }

    /// Signs and uploads the next version of an organization's policy
    /// (owners and admins).
    pub fn set_org_policy(
        &self,
        org_id: &str,
        rules: &passbox_core::policy::PolicyRules,
    ) -> Result<()> {
        self.sync()?;
        let upload = self.with_keyring(|k| k.sign_org_policy(org_id, rules, now_ms()))?;
        self.call(
            "PUT",
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(json!({
                "version": upload.version,
                "policy": upload.policy,
                "signature": upload.signature,
            })),
        )?;
        self.sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_links_parse() {
        assert_eq!(
            parse_invitation_link("https://pb.example/invite/abc#org=XYZ"),
            ("abc".to_owned(), Some("XYZ".to_owned()))
        );
        assert_eq!(parse_invitation_link("abc"), ("abc".to_owned(), None));
        assert_eq!(
            parse_invitation_link("/invite/abc/#x=1&org=R"),
            ("abc".to_owned(), Some("R".to_owned()))
        );
    }
}
