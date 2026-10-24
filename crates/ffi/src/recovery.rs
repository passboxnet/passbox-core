//! Account recovery, emergency access and adding a device by code
//! (additive API, wave C). See `docs/architecture/recovery.md`.
//!
//! Typical flows for the apps:
//!
//! - **Recovery code** (signed out or locked): `start_code_recovery` →
//!   (`complete_recovery_two_factor` when `two_factor_methods` is set) →
//!   `finish_recovery(new_password)` → show the new Emergency Kit with
//!   `RecoveryResult.secret_key` and `.recovery_code`.
//! - **Organization recovery** (new device): `request_org_recovery` → show
//!   `request_code` and ask the member to read it to the admin → poll
//!   `check_org_recovery` until `approved` → `finish_recovery`. Admins:
//!   `recovery_requests` → verify the person and compare `request_code` →
//!   `approve_recovery_request`.
//! - **Emergency access**: grantor `add_emergency_contact` → grantee
//!   `accept_emergency_invitation` → grantor `confirm_emergency_contact`
//!   (returns the fingerprint to compare) → grantee
//!   `request_emergency_access` → after the waiting period (or
//!   `approve_emergency_access`) `open_emergency_access`. Call
//!   `reseal_emergency_access` after unlocking.
//! - **Device code**: signed-in device `start_device_link` (show `code`, as
//!   text and QR code `passbox-link:v1?server=<url>&code=<code>`) → poll
//!   `device_link_status` until `claimed` → ask the user → `approve_device_link`.
//!   New device: `claim_device_link(code)` → poll `poll_device_link` → then
//!   `sign_in(email, master password, secret_key)`.

use passbox_client as client;
use passbox_core::device_link::DeviceLinkRequest;
use passbox_core::recovery::code::RecoveryCode;

use crate::{Item, PassboxClient, Result, item_to_ffi};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryStatus {
    /// When the recovery code was created; `None` without one.
    pub recovery_code_created_at: Option<i64>,
    /// Organizations this account escrowed its key with.
    pub org_escrows: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CodeRecoveryStart {
    pub account_id: String,
    pub email: String,
    /// `totp` and/or `recovery` when the account uses two-factor sign-in.
    pub two_factor_methods: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryResult {
    pub account_id: String,
    pub email: String,
    /// The new Secret Key (the old one no longer works).
    pub secret_key: String,
    /// The new recovery code (an old one no longer works).
    pub recovery_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingOrgRecovery {
    pub request_id: String,
    pub email: String,
    pub org_id: Option<String>,
    /// Four groups of five digits; the member reads it to the admin.
    pub request_code: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OrgRecovery {
    pub org_id: String,
    /// Set up and verified against the organization's roster.
    pub available: bool,
    pub problem: Option<String>,
    /// Fingerprint of the recovery key (8 groups of five digits).
    pub fingerprint: Option<String>,
    pub admins: Vec<String>,
    /// This account holds the recovery key.
    pub can_approve: bool,
    /// This account opted in.
    pub enrolled: bool,
    pub pending_requests: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryRequest {
    pub id: String,
    pub org_id: String,
    pub account_id: String,
    pub email: String,
    pub device_name: String,
    pub ip: String,
    pub created_at: i64,
    pub expires_at: i64,
    /// Compare it with the code on the member's screen before approving.
    pub request_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmergencyContact {
    pub id: String,
    pub grantor_id: String,
    pub grantor_email: String,
    pub grantee_id: Option<String>,
    pub grantee_email: String,
    pub wait_days: u32,
    /// `invited`, `accepted` or `confirmed`.
    pub status: String,
    pub vault_ids: Vec<String>,
    /// Unix ms; 0 when not set.
    pub requested_at: i64,
    pub approved_at: i64,
    pub denied_at: i64,
    pub accessed_at: i64,
    /// When access is (or was) released for the current request; 0 without one.
    pub release_at: i64,
    pub released: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmergencyContacts {
    /// People this account trusts.
    pub granted: Vec<EmergencyContact>,
    /// People who trust this account.
    pub received: Vec<EmergencyContact>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EmergencyVault {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct EmergencyVaults {
    pub grantor_id: String,
    pub vaults: Vec<EmergencyVault>,
    /// Read only.
    pub items: Vec<Item>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkStart {
    pub id: String,
    /// `XXXX-XXXX-XXXX-XXXX`.
    pub code: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceLinkState {
    /// `open`, `claimed` or `approved`.
    pub status: String,
    pub expires_at: i64,
    pub device_name: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LinkedAccount {
    pub email: String,
    pub account_id: String,
    pub secret_key: String,
}

fn contact(c: client::EmergencyContact) -> EmergencyContact {
    EmergencyContact {
        id: c.id,
        grantor_id: c.grantor_id,
        grantor_email: c.grantor_email,
        grantee_id: c.grantee_id,
        grantee_email: c.grantee_email,
        wait_days: c.wait_days,
        status: c.status,
        vault_ids: c.vault_ids,
        requested_at: c.requested_at,
        approved_at: c.approved_at,
        denied_at: c.denied_at,
        accessed_at: c.accessed_at,
        release_at: c.release_at,
        released: c.released,
        created_at: c.created_at,
    }
}

fn pending(p: client::PendingOrgRecovery) -> PendingOrgRecovery {
    PendingOrgRecovery {
        request_id: p.request_id,
        email: p.email,
        org_id: p.org_id,
        request_code: p.request_code,
        created_at: p.created_at,
        expires_at: p.expires_at,
    }
}

/// Whether `input` is a complete account recovery code (`R1-…`, checksum included).
#[uniffi::export]
pub fn is_recovery_code(input: String) -> bool {
    RecoveryCode::is_valid(&input)
}

/// Whether `input` has the shape of a device code (`XXXX-XXXX-XXXX-XXXX`).
#[uniffi::export]
pub fn is_device_code(input: String) -> bool {
    DeviceLinkRequest::is_valid_code(&input)
}

#[uniffi::export]
impl PassboxClient {
    // --- Recovery code -------------------------------------------------------------

    pub fn recovery_status(&self) -> Result<RecoveryStatus> {
        let s = self.inner.recovery_status()?;
        Ok(RecoveryStatus {
            recovery_code_created_at: s.recovery_code_created_at,
            org_escrows: s.org_escrows,
        })
    }

    /// Creates a recovery code (replacing an earlier one); show it once in
    /// the Emergency Kit. `password` is the current master password.
    pub fn create_recovery_code(&self, password: String) -> Result<String> {
        Ok(self.inner.create_recovery_code(&password)?)
    }

    pub fn remove_recovery_code(&self, password: String) -> Result<()> {
        Ok(self.inner.remove_recovery_code(&password)?)
    }

    /// Starts a recovery with the recovery code (signed out or locked).
    pub fn start_code_recovery(&self, email: String, code: String) -> Result<CodeRecoveryStart> {
        let s = self.inner.start_code_recovery(&email, &code)?;
        Ok(CodeRecoveryStart {
            account_id: s.account_id,
            email: s.email,
            two_factor_methods: s.two_factor_methods,
        })
    }

    /// `method`: `totp` (6-digit code) or `recovery` (two-factor recovery code).
    pub fn complete_recovery_two_factor(&self, method: String, code: String) -> Result<()> {
        Ok(self.inner.complete_recovery_two_factor(&method, &code)?)
    }

    pub fn recovery_ready(&self) -> bool {
        self.inner.recovery_ready()
    }

    pub fn cancel_recovery(&self) {
        self.inner.cancel_recovery();
    }

    /// New master password, new Secret Key and recovery code; unlocks.
    pub fn finish_recovery(&self, new_password: String) -> Result<RecoveryResult> {
        let r = self.inner.finish_recovery(&new_password)?;
        Ok(RecoveryResult {
            account_id: r.account_id,
            email: r.email,
            secret_key: r.secret_key,
            recovery_code: r.recovery_code,
        })
    }

    // --- Organization recovery -----------------------------------------------------

    pub fn org_recovery(&self, org_id: String) -> Result<OrgRecovery> {
        let o = self.inner.org_recovery(&org_id)?;
        Ok(OrgRecovery {
            org_id: o.org_id,
            available: o.available,
            problem: o.problem,
            fingerprint: o.fingerprint,
            admins: o.admins,
            can_approve: o.can_approve,
            enrolled: o.enrolled,
            pending_requests: o.pending_requests,
        })
    }

    pub fn set_up_org_recovery(&self, org_id: String) -> Result<()> {
        Ok(self.inner.set_up_org_recovery(&org_id)?)
    }

    pub fn add_recovery_admin(&self, org_id: String, admin_id: String) -> Result<()> {
        Ok(self.inner.add_recovery_admin(&org_id, &admin_id)?)
    }

    /// Opt in: escrows the account key with the organization.
    pub fn enroll_org_recovery(&self, org_id: String) -> Result<()> {
        Ok(self.inner.enroll_org_recovery(&org_id)?)
    }

    pub fn withdraw_org_recovery(&self, org_id: String) -> Result<()> {
        Ok(self.inner.withdraw_org_recovery(&org_id)?)
    }

    pub fn recovery_requests(&self, org_id: String) -> Result<Vec<RecoveryRequest>> {
        Ok(self
            .inner
            .recovery_requests(&org_id)?
            .into_iter()
            .map(|r| RecoveryRequest {
                id: r.id,
                org_id: r.org_id,
                account_id: r.account_id,
                email: r.email,
                device_name: r.device_name,
                ip: r.ip,
                created_at: r.created_at,
                expires_at: r.expires_at,
                request_code: r.request_code,
            })
            .collect())
    }

    /// Approve only after verifying the member out of band and comparing
    /// `request_code`. This device briefly holds the member's account key.
    pub fn approve_recovery_request(&self, org_id: String, request_id: String) -> Result<()> {
        Ok(self.inner.approve_recovery_request(&org_id, &request_id)?)
    }

    pub fn deny_recovery_request(&self, org_id: String, request_id: String) -> Result<()> {
        Ok(self.inner.deny_recovery_request(&org_id, &request_id)?)
    }

    /// From a new device (signed out or locked). Show `request_code`.
    pub fn request_org_recovery(
        &self,
        email: String,
        org_id: Option<String>,
    ) -> Result<PendingOrgRecovery> {
        Ok(pending(
            self.inner.request_org_recovery(&email, org_id.as_deref())?,
        ))
    }

    pub fn pending_org_recovery(&self) -> Result<Option<PendingOrgRecovery>> {
        Ok(self.inner.pending_org_recovery()?.map(pending))
    }

    /// `pending`, `approved` (then `finish_recovery`), `denied`, `expired`,
    /// `cancelled` or `completed`.
    pub fn check_org_recovery(&self) -> Result<String> {
        Ok(self.inner.check_org_recovery()?)
    }

    pub fn cancel_org_recovery(&self) -> Result<()> {
        Ok(self.inner.cancel_org_recovery()?)
    }

    // --- Emergency access ------------------------------------------------------------

    pub fn emergency_contacts(&self) -> Result<EmergencyContacts> {
        let c = self.inner.emergency_contacts()?;
        Ok(EmergencyContacts {
            granted: c.granted.into_iter().map(contact).collect(),
            received: c.received.into_iter().map(contact).collect(),
        })
    }

    /// `wait_days`: 1–30 (7 is the default the web app offers).
    pub fn add_emergency_contact(&self, email: String, wait_days: u32) -> Result<String> {
        Ok(self.inner.add_emergency_contact(&email, wait_days)?)
    }

    /// Returns the contact's key fingerprint (compare it with them).
    pub fn confirm_emergency_contact(
        &self,
        grant_id: String,
        vault_ids: Vec<String>,
    ) -> Result<String> {
        Ok(self
            .inner
            .confirm_emergency_contact(&grant_id, &vault_ids)?)
    }

    /// Call after unlocking; returns how many grants were sealed again.
    pub fn reseal_emergency_access(&self) -> Result<u32> {
        Ok(self.inner.reseal_emergency_access()?)
    }

    pub fn remove_emergency_contact(&self, grant_id: String) -> Result<()> {
        Ok(self.inner.remove_emergency_contact(&grant_id)?)
    }

    pub fn accept_emergency_invitation(&self, grant_id: String) -> Result<()> {
        Ok(self.inner.accept_emergency_invitation(&grant_id)?)
    }

    pub fn request_emergency_access(&self, grant_id: String) -> Result<()> {
        Ok(self.inner.request_emergency_access(&grant_id)?)
    }

    pub fn approve_emergency_access(&self, grant_id: String) -> Result<()> {
        Ok(self.inner.approve_emergency_access(&grant_id)?)
    }

    pub fn deny_emergency_access(&self, grant_id: String) -> Result<()> {
        Ok(self.inner.deny_emergency_access(&grant_id)?)
    }

    /// The released vaults, decrypted on this device (read only, not stored).
    pub fn open_emergency_access(&self, grant_id: String) -> Result<EmergencyVaults> {
        let v = self.inner.open_emergency_access(&grant_id)?;
        Ok(EmergencyVaults {
            grantor_id: v.grantor_id,
            vaults: v
                .vaults
                .into_iter()
                .map(|(id, name)| EmergencyVault { id, name })
                .collect(),
            items: v.items.into_iter().map(item_to_ffi).collect(),
            errors: v.errors,
        })
    }

    // --- Device codes ------------------------------------------------------------------

    pub fn start_device_link(&self) -> Result<DeviceLinkStart> {
        let l = self.inner.start_device_link()?;
        Ok(DeviceLinkStart {
            id: l.id,
            code: l.code,
            expires_at: l.expires_at,
        })
    }

    pub fn device_link_status(&self, link_id: String) -> Result<DeviceLinkState> {
        let s = self.inner.device_link_status(&link_id)?;
        Ok(DeviceLinkState {
            status: s.status,
            expires_at: s.expires_at,
            device_name: s.device_name,
            ip: s.ip,
        })
    }

    pub fn approve_device_link(&self, link_id: String) -> Result<()> {
        Ok(self.inner.approve_device_link(&link_id)?)
    }

    pub fn cancel_device_link(&self, link_id: String) -> Result<()> {
        Ok(self.inner.cancel_device_link(&link_id)?)
    }

    pub fn claim_device_link(&self, code: String) -> Result<()> {
        Ok(self.inner.claim_device_link(&code)?)
    }

    /// `None` while waiting for the approval.
    pub fn poll_device_link(&self) -> Result<Option<LinkedAccount>> {
        Ok(self.inner.poll_device_link()?.map(|a| LinkedAccount {
            email: a.email,
            account_id: a.account_id,
            secret_key: a.secret_key,
        }))
    }
}
