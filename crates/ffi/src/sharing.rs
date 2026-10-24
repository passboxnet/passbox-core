//! Organizations, invitations, groups and shared vaults (additive API).
//!
//! Roles and members shown here are verified by the Rust core (signed
//! attestations and manifests); `server_role` is what the server enforces.
//! See `docs/architecture/sharing.md`.

use passbox_client as client;
use passbox_core::sharing::objects::PrincipalType;

use crate::{PassboxClient, Result};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgMember {
    pub account_id: String,
    pub email: Option<String>,
    /// `owner`, `admin`, `member` or `guest`.
    pub role: String,
    /// `accepted` (waiting for confirmation), `confirmed` or `suspended`.
    pub status: String,
    /// Fingerprint of the member's key (12 groups of five digits).
    pub fingerprint: Option<String>,
    /// The key is attested by the owner or an admin.
    pub verified: bool,
    /// The key differs from the one pinned on this device.
    pub key_changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgGroup {
    pub id: String,
    pub name: Option<String>,
    pub key_version: u32,
    pub members: Vec<String>,
    /// Members come from signed grants (only known to group members).
    pub members_verified: bool,
    pub verified: bool,
    /// This account holds the group's current key.
    pub is_member: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Org {
    pub id: String,
    /// `family` or `team`.
    pub kind: String,
    pub name: Option<String>,
    /// This account's role and status.
    pub role: String,
    pub status: String,
    /// The family vault of a family organization.
    pub default_vault_id: Option<String>,
    /// Organization fingerprint (8 groups of five digits), as in invitation links.
    pub fingerprint: String,
    pub verified: bool,
    pub members: Vec<OrgMember>,
    pub groups: Vec<OrgGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SharedVaultMember {
    /// `account` or `group`.
    pub principal_type: String,
    pub principal_id: String,
    /// `view`, `edit` or `manage`.
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SharedVault {
    pub vault_id: String,
    pub org_id: String,
    /// Role from the verified member list; `None` if unverified.
    pub role: Option<String>,
    /// Role the server enforces.
    pub server_role: String,
    pub key_epoch: u32,
    pub members: Vec<SharedVaultMember>,
    pub verified: bool,
    pub has_key: bool,
    /// A member was removed; a manager must rotate the key.
    pub rotation_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SharingWarning {
    /// For example `key_changed`, `org_root_changed`, `grant_invalid`,
    /// `manifest_invalid`, `role_mismatch`.
    pub kind: String,
    pub subject_id: String,
    pub org_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultAccess {
    pub vault_id: String,
    /// `None` for personal vaults.
    pub org_id: Option<String>,
    pub role: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Invitation {
    pub id: String,
    pub token: String,
    /// Link with the organization fingerprint; pass it on through a channel you trust.
    pub link: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingInvitation {
    pub id: String,
    pub email: String,
    pub role: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct KeyLookup {
    pub account_id: String,
    pub fingerprint: String,
    /// `new` (now pinned), `unchanged` or `changed`.
    pub status: String,
    pub previous_fingerprint: Option<String>,
}

fn org(o: client::OrgView) -> Org {
    Org {
        id: o.id,
        kind: o.kind,
        name: o.name,
        role: o.role,
        status: o.status,
        default_vault_id: o.default_vault_id,
        fingerprint: o.fingerprint,
        verified: o.verified,
        members: o
            .members
            .into_iter()
            .map(|m| OrgMember {
                account_id: m.account_id,
                email: m.email,
                role: m.role,
                status: m.status,
                fingerprint: m.fingerprint,
                verified: m.verified,
                key_changed: m.key_changed,
            })
            .collect(),
        groups: o
            .groups
            .into_iter()
            .map(|g| OrgGroup {
                id: g.id,
                name: g.name,
                key_version: g.key_version,
                members: g.members,
                members_verified: g.members_verified,
                verified: g.verified,
                is_member: g.is_member,
            })
            .collect(),
    }
}

fn shared_vault(v: client::SharedVaultView) -> SharedVault {
    SharedVault {
        vault_id: v.vault_id,
        org_id: v.org_id,
        role: v.role,
        server_role: v.server_role,
        key_epoch: v.key_epoch,
        members: v
            .members
            .into_iter()
            .map(|m| SharedVaultMember {
                principal_type: m.principal_type,
                principal_id: m.principal_id,
                role: m.role,
            })
            .collect(),
        verified: v.verified,
        has_key: v.has_key,
        rotation_pending: v.rotation_pending,
    }
}

fn lookup(l: client::DirectoryLookup) -> KeyLookup {
    KeyLookup {
        account_id: l.account_id,
        fingerprint: l.fingerprint,
        status: l.status,
        previous_fingerprint: l.previous_fingerprint,
    }
}

#[uniffi::export]
impl PassboxClient {
    /// Organizations with verified members and groups.
    pub fn orgs(&self) -> Result<Vec<Org>> {
        Ok(self.inner.orgs()?.into_iter().map(org).collect())
    }

    /// Shared vaults with verified members, roles and key state.
    pub fn shared_vaults(&self) -> Result<Vec<SharedVault>> {
        Ok(self
            .inner
            .shared_vaults()?
            .into_iter()
            .map(shared_vault)
            .collect())
    }

    /// Problems found while verifying sharing data, for example a changed key.
    pub fn sharing_warnings(&self) -> Result<Vec<SharingWarning>> {
        Ok(self
            .inner
            .sharing_warnings()?
            .into_iter()
            .map(|w| SharingWarning {
                kind: w.kind,
                subject_id: w.subject_id,
                org_id: w.org_id,
                message: w.message,
            })
            .collect())
    }

    /// Ownership (personal or organization) and this account's role.
    pub fn vault_access(&self, vault_id: String) -> Result<VaultAccess> {
        let a = self.inner.vault_access(&vault_id)?;
        Ok(VaultAccess {
            vault_id: a.vault_id,
            org_id: a.org_id,
            role: a.role,
            verified: a.verified,
        })
    }

    /// Fingerprint of this account's own keys.
    pub fn own_fingerprint(&self) -> Result<String> {
        Ok(self.inner.own_fingerprint()?)
    }

    /// Looks up and verifies an account's key in the key directory.
    pub fn lookup_key(&self, account_id: String) -> Result<KeyLookup> {
        Ok(lookup(self.inner.lookup_key(&account_id)?))
    }

    /// Checks that the key directory lists this account's own key.
    pub fn verify_own_key(&self) -> Result<KeyLookup> {
        Ok(lookup(self.inner.verify_own_key()?))
    }

    /// Trusts the current key of an account after a change; returns its fingerprint.
    pub fn accept_key_change(&self, account_id: String) -> Result<String> {
        Ok(self.inner.accept_key_change(&account_id)?)
    }

    /// Creates a family with its shared family vault; returns the organization ID.
    pub fn create_family(&self, name: String, vault_name: String) -> Result<String> {
        Ok(self.inner.create_family(&name, &vault_name)?)
    }

    pub fn create_team(&self, name: String) -> Result<String> {
        Ok(self.inner.create_team(&name)?)
    }

    pub fn rename_org(&self, org_id: String, name: String) -> Result<()> {
        Ok(self.inner.rename_org(&org_id, &name)?)
    }

    pub fn delete_org(&self, org_id: String) -> Result<()> {
        Ok(self.inner.delete_org(&org_id)?)
    }

    /// Invites by email (`admin`, `member` or `guest`); returns the link.
    pub fn invite(&self, org_id: String, email: String, role: String) -> Result<Invitation> {
        let i = self.inner.invite(&org_id, &email, &role)?;
        Ok(Invitation {
            id: i.id,
            token: i.token,
            link: i.link,
            expires_at: i.expires_at,
        })
    }

    pub fn invitations(&self, org_id: String) -> Result<Vec<PendingInvitation>> {
        Ok(self
            .inner
            .invitations(&org_id)?
            .into_iter()
            .map(|i| PendingInvitation {
                id: i.id,
                email: i.email,
                role: i.role,
                created_at: i.created_at,
                expires_at: i.expires_at,
            })
            .collect())
    }

    pub fn revoke_invitation(&self, org_id: String, invitation_id: String) -> Result<()> {
        Ok(self.inner.revoke_invitation(&org_id, &invitation_id)?)
    }

    /// Accepts an invitation link (or token); returns the organization ID.
    pub fn accept_invitation(&self, link: String) -> Result<String> {
        Ok(self.inner.accept_invitation(&link)?)
    }

    /// Confirms an accepted member (admins); returns the attested fingerprint.
    pub fn confirm_member(&self, org_id: String, account_id: String) -> Result<String> {
        Ok(self.inner.confirm_member(&org_id, &account_id)?)
    }

    pub fn set_member_role(&self, org_id: String, account_id: String, role: String) -> Result<()> {
        Ok(self.inner.set_member_role(&org_id, &account_id, &role)?)
    }

    pub fn suspend_member(&self, org_id: String, account_id: String) -> Result<()> {
        Ok(self.inner.suspend_member(&org_id, &account_id)?)
    }

    pub fn reactivate_member(&self, org_id: String, account_id: String) -> Result<()> {
        Ok(self.inner.reactivate_member(&org_id, &account_id)?)
    }

    /// Removes a member and rotates every key they had.
    pub fn remove_member(&self, org_id: String, account_id: String) -> Result<()> {
        Ok(self.inner.remove_member(&org_id, &account_id)?)
    }

    pub fn leave_org(&self, org_id: String) -> Result<()> {
        Ok(self.inner.leave_org(&org_id)?)
    }

    pub fn create_shared_vault(&self, org_id: String, name: String) -> Result<String> {
        Ok(self.inner.create_shared_vault(&org_id, &name)?)
    }

    /// Shares with `account` or `group` as `view`, `edit` or `manage` (or changes the role).
    pub fn share_vault(
        &self,
        vault_id: String,
        principal_type: String,
        principal_id: String,
        role: String,
    ) -> Result<()> {
        Ok(self
            .inner
            .share_vault(&vault_id, &principal_type, &principal_id, &role)?)
    }

    /// Removes a member from a vault (rotates the key, re-encrypts items).
    pub fn unshare_vault(
        &self,
        vault_id: String,
        principal_type: String,
        principal_id: String,
    ) -> Result<()> {
        Ok(self
            .inner
            .unshare_vault(&vault_id, &principal_type, &principal_id)?)
    }

    /// Rotates a vault's key, for example when `rotation_pending` is set.
    pub fn rotate_vault_key(&self, vault_id: String) -> Result<()> {
        let none: [(PrincipalType, String); 0] = [];
        Ok(self.inner.rotate_vault_key(&vault_id, &none)?)
    }

    pub fn create_group(
        &self,
        org_id: String,
        name: String,
        members: Vec<String>,
    ) -> Result<String> {
        Ok(self.inner.create_group(&org_id, &name, &members)?)
    }

    pub fn rename_group(&self, org_id: String, group_id: String, name: String) -> Result<()> {
        Ok(self.inner.rename_group(&org_id, &group_id, &name)?)
    }

    pub fn delete_group(&self, org_id: String, group_id: String) -> Result<()> {
        Ok(self.inner.delete_group(&org_id, &group_id)?)
    }

    pub fn add_group_member(
        &self,
        org_id: String,
        group_id: String,
        account_id: String,
    ) -> Result<()> {
        Ok(self
            .inner
            .add_group_member(&org_id, &group_id, &account_id)?)
    }

    pub fn remove_group_member(
        &self,
        org_id: String,
        group_id: String,
        account_id: String,
    ) -> Result<()> {
        Ok(self
            .inner
            .remove_group_member(&org_id, &group_id, &account_id)?)
    }
}
