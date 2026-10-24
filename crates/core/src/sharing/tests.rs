//! End-to-end tests of organizations, groups and shared vaults against an
//! in-memory stand-in for the server, including a server that lies.

use std::collections::BTreeMap;

use super::build::{NewOrg, VaultKeyUpload, VaultMemberChange};
use super::data::*;
use super::objects::{
    OrgKind, OrgRole, PrincipalType, Signed, VaultGrant, VaultManifest, VaultRole,
};
use crate::aead::SymmetricKey;
use crate::directory::{LogHead, LogSigner, LookupResponse, append};
use crate::identity::{EncryptionKey, SignatureKey, SignedBundle};
use crate::keyring::Keyring;
use crate::sharing::objects::Canonical;
use crate::{encoding, id};

/// A minimal honest server: stores what clients upload and hands every
/// account the rows it may see.
#[derive(Default)]
struct Server {
    bundles: BTreeMap<String, SignedBundle>,
    log: Vec<crate::directory::LogEntry>,
    orgs: BTreeMap<String, OrgRecord>,
    members: BTreeMap<String, Vec<RosterMember>>,
    org_keys: Vec<(String, OrgKeyRecord)>,
    groups: BTreeMap<String, GroupRecord>,
    group_keys: Vec<(String, GroupKeyRecord)>,
    access: BTreeMap<String, (String, u32)>,
    vault_members: BTreeMap<String, Vec<(String, String, String)>>,
    vault_keys: Vec<VaultKeyRecord>,
    manifests: BTreeMap<String, Vec<ManifestRecord>>,
}

fn signer() -> LogSigner {
    LogSigner::from_seed(&[9; 32])
}

impl Server {
    fn publish(&mut self, keyring: &mut Keyring) {
        let upload = keyring.create_account_keys(1).unwrap();
        let bundle = SignedBundle::parse(&upload.bundle, &upload.bundle_signature).unwrap();
        let prev = self.log.last().map_or([0; 32], |e| e.hash().unwrap());
        self.log.push(append(
            &prev,
            self.log.len() as u64 + 1,
            keyring.account_id(),
            1,
            &bundle.hash(),
        ));
        self.bundles.insert(keyring.account_id().to_owned(), bundle);
    }

    fn lookup(&self, account_id: &str, since: u64) -> LookupResponse {
        let index = self
            .log
            .iter()
            .rposition(|e| e.account_id == account_id)
            .unwrap();
        let seq = index as u64 + 1;
        let from = if since == 0 { seq } else { seq.min(since + 1) };
        let bundle = &self.bundles[account_id];
        LookupResponse {
            bundle: bundle.encoded(),
            bundle_signature: bundle.encoded_signature(),
            seq,
            entries: self.log[from as usize - 1..].to_vec(),
            head: signer().sign(&LogHead {
                size: self.log.len() as u64,
                root: self.log.last().unwrap().hash().unwrap(),
                timestamp: 1,
            }),
        }
    }

    fn roster_member(&self, account_id: &str, role: &str, status: &str) -> RosterMember {
        let bundle = &self.bundles[account_id];
        RosterMember {
            account_id: account_id.to_owned(),
            role: role.to_owned(),
            status: status.to_owned(),
            email: Some(format!("{account_id}@example.com")),
            bundle: Some(bundle.encoded()),
            bundle_signature: Some(bundle.encoded_signature()),
            attestation: None,
            attestation_signature: None,
        }
    }

    fn create_org(&mut self, owner: &str, org: &NewOrg) {
        self.orgs.insert(
            org.id.clone(),
            OrgRecord {
                id: org.id.clone(),
                kind: org.kind.clone(),
                role: "owner".into(),
                status: "confirmed".into(),
                genesis: org.genesis.clone(),
                genesis_signature: org.genesis_signature.clone(),
                encrypted_meta: org.encrypted_meta.clone(),
                meta_epoch: org.meta_epoch,
                revision: 1,
                default_vault_id: org.vault.as_ref().map(|v| v.id.clone()),
            },
        );
        self.members.insert(
            org.id.clone(),
            vec![self.roster_member(owner, "owner", "confirmed")],
        );
        self.add_org_key(&org.id, &org.org_key);
        if let Some(vault) = &org.vault {
            self.access.insert(vault.id.clone(), (org.id.clone(), 1));
            self.vault_members.insert(
                vault.id.clone(),
                vec![("account".into(), owner.to_owned(), "manage".into())],
            );
            self.add_manifest(&vault.id, &vault.manifest, &vault.manifest_signature);
            for key in &vault.keys {
                self.add_vault_key(&vault.id, key);
            }
        }
    }

    fn add_org_key(&mut self, org_id: &str, key: &super::build::OrgKeyUpload) {
        self.org_keys.push((
            key.account_id.clone(),
            OrgKeyRecord {
                org_id: org_id.to_owned(),
                epoch: key.epoch,
                sealed_key: key.sealed_key.clone(),
                grant: key.grant.clone(),
                grant_signature: key.grant_signature.clone(),
            },
        ));
    }

    fn add_manifest(&mut self, vault_id: &str, manifest: &str, signature: &str) {
        let chain = self.manifests.entry(vault_id.to_owned()).or_default();
        chain.push(ManifestRecord {
            vault_id: vault_id.to_owned(),
            version: chain.len() as u64 + 1,
            manifest: manifest.to_owned(),
            signature: signature.to_owned(),
        });
    }

    fn add_vault_key(&mut self, vault_id: &str, key: &VaultKeyUpload) {
        self.vault_keys.retain(|k| {
            !(k.vault_id == vault_id
                && k.key_epoch == key.key_epoch
                && k.principal_type == key.principal_type
                && k.principal_id == key.principal_id)
        });
        self.vault_keys.push(VaultKeyRecord {
            vault_id: vault_id.to_owned(),
            key_epoch: key.key_epoch,
            principal_type: key.principal_type.clone(),
            principal_id: key.principal_id.clone(),
            sealed_key: key.sealed_key.clone(),
            wrapped_key: key.wrapped_key.clone(),
            grant: key.grant.clone(),
            grant_signature: key.grant_signature.clone(),
        });
    }

    fn accept(&mut self, org_id: &str, account_id: &str, role: &str) {
        let member = self.roster_member(account_id, role, "accepted");
        self.members.get_mut(org_id).unwrap().push(member);
    }

    fn confirm(&mut self, org_id: &str, account_id: &str, c: &super::build::ConfirmMember) {
        let member = self
            .members
            .get_mut(org_id)
            .unwrap()
            .iter_mut()
            .find(|m| m.account_id == account_id)
            .unwrap();
        member.status = "confirmed".into();
        member.attestation = Some(c.attestation.clone());
        member.attestation_signature = Some(c.attestation_signature.clone());
        self.add_org_key(org_id, &c.org_key);
    }

    fn share(&mut self, vault_id: &str, change: &VaultMemberChange) {
        let members = self.vault_members.get_mut(vault_id).unwrap();
        members.retain(|(t, id, _)| !(*t == change.principal_type && *id == change.principal_id));
        members.push((
            change.principal_type.clone(),
            change.principal_id.clone(),
            change.role.clone(),
        ));
        self.add_manifest(vault_id, &change.manifest, &change.manifest_signature);
        self.add_vault_key(vault_id, &change.key);
    }

    fn groups_of(&self, account_id: &str) -> Vec<String> {
        self.group_keys
            .iter()
            .filter(|(a, k)| {
                a == account_id && self.groups[&k.group_id].key_version == k.key_version
            })
            .map(|(_, k)| k.group_id.clone())
            .collect()
    }

    fn delta(&self, account_id: &str) -> SharingDelta {
        let orgs: Vec<OrgRecord> = self
            .orgs
            .values()
            .filter_map(|o| {
                let me = self.members[&o.id]
                    .iter()
                    .find(|m| m.account_id == account_id)?;
                Some(OrgRecord {
                    role: me.role.clone(),
                    status: me.status.clone(),
                    ..o.clone()
                })
            })
            .collect();
        let my_groups = self.groups_of(account_id);
        let vault_access = self
            .vault_members
            .iter()
            .filter_map(|(vault, members)| {
                let role = members
                    .iter()
                    .filter(|(t, id, _)| {
                        (t == "account" && id == account_id)
                            || (t == "group" && my_groups.contains(id))
                    })
                    .map(|(_, _, r)| VaultRole::parse(r).unwrap())
                    .max()?;
                let (org, epoch) = &self.access[vault];
                Some(VaultAccessRecord {
                    vault_id: vault.clone(),
                    org_id: org.clone(),
                    role: role.as_str().into(),
                    key_epoch: *epoch,
                    rotation_pending: false,
                })
            })
            .collect::<Vec<_>>();
        SharingDelta {
            rosters: orgs
                .iter()
                .map(|o| RosterRecord {
                    org_id: o.id.clone(),
                    members: self.members[&o.id].clone(),
                })
                .collect(),
            org_keys: self
                .org_keys
                .iter()
                .filter(|(a, _)| a == account_id)
                .map(|(_, k)| k.clone())
                .collect(),
            groups: self
                .groups
                .values()
                .filter(|g| orgs.iter().any(|o| o.id == g.org_id))
                .cloned()
                .collect(),
            group_keys: self
                .group_keys
                .iter()
                .filter(|(a, _)| a == account_id)
                .map(|(_, k)| k.clone())
                .collect(),
            vault_keys: self
                .vault_keys
                .iter()
                .filter(|k| {
                    vault_access.iter().any(|a| a.vault_id == k.vault_id)
                        && ((k.principal_type == "account" && k.principal_id == account_id)
                            || (k.principal_type == "group" && my_groups.contains(&k.principal_id)))
                })
                .cloned()
                .collect(),
            manifests: vault_access
                .iter()
                .flat_map(|a| self.manifests[&a.vault_id].clone())
                .collect(),
            vault_access,
            orgs,
            signers: self
                .bundles
                .values()
                .map(|b| BundleRecord {
                    bundle: b.encoded(),
                    bundle_signature: b.encoded_signature(),
                })
                .collect(),
        }
    }
}

fn account() -> Keyring {
    let auk = SymmetricKey::generate().unwrap();
    Keyring::create(&auk, &id::new_id().unwrap()).unwrap().0
}

fn warnings(report: &super::state::SharingReport, kind: &str) -> usize {
    report
        .view
        .warnings
        .iter()
        .filter(|w| w.kind == kind)
        .count()
}

/// Alice creates a family with its vault, invites and confirms Bob, and
/// shares the vault with him.
fn family() -> (Server, Keyring, Keyring, String, String) {
    let mut server = Server::default();
    let mut alice = account();
    let mut bob = account();
    server.publish(&mut alice);
    server.publish(&mut bob);
    let org = alice
        .create_org(
            OrgKind::Family,
            r#"{"name":"Doe family"}"#,
            Some(r#"{"name":"Family"}"#),
            10,
        )
        .unwrap();
    server.create_org(alice.account_id(), &org);
    let vault_id = org.vault.as_ref().unwrap().id.clone();
    let report = alice.apply_sharing(server.delta(alice.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    let org_view = &report.view.orgs[0];
    assert!(org_view.verified);
    assert_eq!(org_view.name.as_deref(), Some("Doe family"));
    assert_eq!(report.view.vaults[0].role.as_deref(), Some("manage"));
    assert!(report.view.vaults[0].has_key);

    // Bob accepts the invitation (the link carries the org fingerprint).
    let (root, _) = alice.org_fingerprint(&org.id).unwrap();
    bob.pin_org_root(&org.id, &root).unwrap();
    server.accept(&org.id, bob.account_id(), "member");
    alice.apply_sharing(server.delta(alice.account_id()));

    // Alice must look Bob up in the directory before confirming him.
    assert!(alice.confirm_member(&org.id, bob.account_id(), 11).is_err());
    let lookup = alice
        .verify_directory_lookup(bob.account_id(), &server.lookup(bob.account_id(), 0))
        .unwrap();
    assert_eq!(lookup.status, "new");
    let confirm = alice.confirm_member(&org.id, bob.account_id(), 11).unwrap();
    assert_eq!(confirm.fingerprint, lookup.fingerprint);
    assert_eq!(confirm.fingerprint, bob.own_bundle().unwrap().fingerprint());
    server.confirm(&org.id, bob.account_id(), &confirm);
    alice.apply_sharing(server.delta(alice.account_id()));

    let change = alice
        .share_vault(
            &vault_id,
            PrincipalType::Account,
            bob.account_id(),
            VaultRole::Edit,
            12,
        )
        .unwrap();
    server.share(&vault_id, &change);
    alice.apply_sharing(server.delta(alice.account_id()));
    (server, alice, bob, org.id, vault_id)
}

#[test]
fn family_sharing_end_to_end() {
    let (server, alice, mut bob, org_id, vault_id) = family();
    let item = alice
        .encrypt_item_at(&vault_id, 1, "item1", 1, r#"{"title":"Netflix"}"#)
        .unwrap();

    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    let vault = &report.view.vaults[0];
    assert_eq!(vault.role.as_deref(), Some("edit"));
    assert!(vault.has_key);
    assert_eq!(report.wrapped_keys.len(), 1);
    assert_eq!(
        bob.decrypt_item_at(&vault_id, 1, "item1", 1, &item)
            .unwrap(),
        r#"{"title":"Netflix"}"#
    );
    let org = &report.view.orgs[0];
    assert_eq!(org.name.as_deref(), Some("Doe family"));
    assert_eq!(org.members.len(), 2);
    assert!(org.members.iter().all(|m| m.verified && !m.key_changed));
    assert_eq!(org.id, org_id);
    // Bob is not a manager: he cannot share further.
    assert!(
        bob.share_vault(
            &vault_id,
            PrincipalType::Account,
            alice.account_id(),
            VaultRole::View,
            13
        )
        .is_err()
    );
    // Session exports keep key pairs and shared vault keys.
    let (key, blob) = bob.export_session().unwrap();
    let fresh = Keyring::import_session(&key, bob.account_id(), &blob).unwrap();
    assert!(fresh.has_account_keys());
    assert!(fresh.has_vault_key(&vault_id, 1));
}

#[test]
fn forged_grants_and_swapped_keys_are_rejected() {
    let (mut server, _alice, mut bob, org_id, vault_id) = family();

    // A malicious server replaces Bob's grant with one it signed itself.
    let mallory = SignatureKey::generate().unwrap();
    let key = server
        .vault_keys
        .iter_mut()
        .find(|k| k.principal_id == bob.account_id())
        .unwrap();
    let mut grant = Signed::<VaultGrant>::parse(&key.grant, &key.grant_signature)
        .unwrap()
        .value;
    let honest = key.clone();
    grant.role = VaultRole::Manage;
    let forged = Signed::sign(grant, &mallory);
    key.grant = forged.encoded();
    key.grant_signature = forged.encoded_signature();
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(warnings(&report, "grant_invalid") > 0);
    assert!(!bob.has_vault_key(&vault_id, 1));

    // The server seals its own key for Bob under the honest grant.
    let key = server
        .vault_keys
        .iter_mut()
        .find(|k| k.principal_id == bob.account_id())
        .unwrap();
    *key = honest.clone();
    let bundle = bob.own_bundle().unwrap().clone();
    let evil_key = SymmetricKey::generate().unwrap();
    key.sealed_key = encoding::encode(
        &bundle
            .seal(
                "vault-key",
                &super::objects::seal_context::vault_key(
                    &vault_id,
                    1,
                    PrincipalType::Account,
                    bob.account_id(),
                ),
                evil_key.as_bytes(),
            )
            .unwrap(),
    );
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(warnings(&report, "grant_invalid") > 0);
    assert!(!bob.has_vault_key(&vault_id, 1));

    // A manifest version signed by a non-manager (Bob has edit only) is
    // rejected, and so is a manifest chain without the pinned version.
    *server
        .vault_keys
        .iter_mut()
        .find(|k| k.principal_id == bob.account_id())
        .unwrap() = honest;
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert!(bob.has_vault_key(&vault_id, 1));
    let latest = server.manifests[&vault_id].last().unwrap().clone();
    let mut manifest = Signed::<VaultManifest>::parse(&latest.manifest, &latest.signature)
        .unwrap()
        .value;
    manifest.version += 1;
    manifest.prev_hash = Signed::<VaultManifest>::parse(&latest.manifest, &latest.signature)
        .unwrap()
        .hash();
    manifest.signer_id = bob.account_id().to_owned();
    let bob_sig = SignatureKey::generate().unwrap();
    let forged = Signed::sign(manifest, &bob_sig);
    server.add_manifest(&vault_id, &forged.encoded(), &forged.encoded_signature());
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(warnings(&report, "manifest_invalid") > 0);
    assert!(!report.view.vaults[0].verified);
    server.manifests.get_mut(&vault_id).unwrap().pop();
    // Rollback: drop the version Bob has seen.
    server.manifests.get_mut(&vault_id).unwrap().pop();
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(warnings(&report, "manifest_invalid") > 0);
    let _ = org_id;
}

#[test]
fn server_cannot_add_members_or_swap_the_organization() {
    let (mut server, _alice, mut bob, org_id, _vault_id) = family();
    bob.apply_sharing(server.delta(bob.account_id()));

    // The server adds Mallory as a "confirmed admin" without attestation.
    let mut mallory = account();
    server.publish(&mut mallory);
    let mut fake = server.roster_member(mallory.account_id(), "admin", "confirmed");
    // ... and with an attestation it signed itself.
    let att = Signed::sign(
        super::objects::MemberAttestation {
            org_id: org_id.clone(),
            account_id: mallory.account_id().to_owned(),
            key_version: 1,
            bundle_hash: server.bundles[mallory.account_id()].hash(),
            role: OrgRole::Admin,
            attester_id: mallory.account_id().to_owned(),
            created_at: 1,
        },
        &SignatureKey::generate().unwrap(),
    );
    fake.attestation = Some(att.encoded());
    fake.attestation_signature = Some(att.encoded_signature());
    server.members.get_mut(&org_id).unwrap().push(fake);
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    let org = &report.view.orgs[0];
    let m = org
        .members
        .iter()
        .find(|m| m.account_id == mallory.account_id())
        .unwrap();
    assert!(!m.verified);
    assert!(warnings(&report, "member_unverified") > 0);

    // A different genesis for the same organization ID is detected.
    let evil = mallory.create_org(OrgKind::Family, "{}", None, 1).unwrap();
    let record = server.orgs.get_mut(&org_id).unwrap();
    record.genesis = evil.genesis;
    record.genesis_signature = evil.genesis_signature;
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(warnings(&report, "org_root_changed") > 0 || warnings(&report, "org_unverified") > 0);
    assert!(!report.view.orgs[0].verified);
}

#[test]
fn key_changes_are_reported_to_people_who_pinned_the_key() {
    let (mut server, mut alice, mut bob, org_id, _vault) = family();
    bob.apply_sharing(server.delta(bob.account_id()));
    // The server swaps Bob's key in the roster (no valid attestation): Alice
    // sees him unverified; with Alice re-attesting a new key (as after an
    // account reset), Carol, who pinned the old key, sees a key change.
    let mut carol = account();
    server.publish(&mut carol);
    server.accept(&org_id, carol.account_id(), "member");
    alice.apply_sharing(server.delta(alice.account_id()));
    alice
        .verify_directory_lookup(carol.account_id(), &server.lookup(carol.account_id(), 0))
        .unwrap();
    let c = alice
        .confirm_member(&org_id, carol.account_id(), 20)
        .unwrap();
    server.confirm(&org_id, carol.account_id(), &c);
    let report = carol.apply_sharing(server.delta(carol.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );

    let enc = EncryptionKey::generate().unwrap();
    let sig = SignatureKey::generate().unwrap();
    let new_bundle = SignedBundle::create(bob.account_id(), 1, &enc, &sig, 99);
    server
        .bundles
        .insert(bob.account_id().to_owned(), new_bundle.clone());
    let member = server
        .members
        .get_mut(&org_id)
        .unwrap()
        .iter_mut()
        .find(|m| m.account_id == bob.account_id())
        .unwrap();
    member.bundle = Some(new_bundle.encoded());
    member.bundle_signature = Some(new_bundle.encoded_signature());
    let report = carol.apply_sharing(server.delta(carol.account_id()));
    let bob_view = report.view.orgs[0]
        .members
        .iter()
        .find(|m| m.account_id == bob.account_id())
        .unwrap();
    assert!(
        !bob_view.verified,
        "the old attestation does not cover the new key"
    );

    let attestation = Signed::sign(
        super::objects::MemberAttestation {
            org_id: org_id.clone(),
            account_id: bob.account_id().to_owned(),
            key_version: 1,
            bundle_hash: new_bundle.hash(),
            role: OrgRole::Member,
            attester_id: alice.account_id().to_owned(),
            created_at: 30,
        },
        &alice.account.as_ref().unwrap().sig,
    );
    let member = server
        .members
        .get_mut(&org_id)
        .unwrap()
        .iter_mut()
        .find(|m| m.account_id == bob.account_id())
        .unwrap();
    member.attestation = Some(attestation.encoded());
    member.attestation_signature = Some(attestation.encoded_signature());
    let report = carol.apply_sharing(server.delta(carol.account_id()));
    assert_eq!(warnings(&report, "key_changed"), 1);
    // Sharing with a changed key is refused until the change is accepted.
    carol.accept_key_change(bob.account_id()).unwrap();
    let report = carol.evaluate_sharing();
    assert_eq!(warnings(&report, "key_changed"), 0);
    // Bob himself notices that the organization lists another key for him.
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(warnings(&report, "own_key_changed") > 0);
}

#[test]
fn groups_and_rotation_after_removal() {
    let (mut server, mut alice, mut bob, org_id, vault_id) = family();
    let mut carol = account();
    server.publish(&mut carol);
    server.accept(&org_id, carol.account_id(), "member");
    alice.apply_sharing(server.delta(alice.account_id()));
    alice
        .verify_directory_lookup(carol.account_id(), &server.lookup(carol.account_id(), 0))
        .unwrap();
    let c = alice
        .confirm_member(&org_id, carol.account_id(), 20)
        .unwrap();
    server.confirm(&org_id, carol.account_id(), &c);
    alice.apply_sharing(server.delta(alice.account_id()));

    // A group with Carol; the vault is shared with the group (view).
    let group = alice
        .create_group(
            &org_id,
            r#"{"name":"Kids"}"#,
            &[carol.account_id().to_owned()],
            21,
        )
        .unwrap();
    assert_eq!(group.members.len(), 2, "creator is a member");
    server.groups.insert(
        group.id.clone(),
        GroupRecord {
            id: group.id.clone(),
            org_id: org_id.clone(),
            key_version: 1,
            bundle: group.bundle.clone(),
            bundle_signature: group.bundle_signature.clone(),
            encrypted_meta: group.encrypted_meta.clone(),
            meta_epoch: group.meta_epoch,
            member_grants: group
                .members
                .iter()
                .map(|m| GrantRecord {
                    grant: m.grant.clone(),
                    grant_signature: m.grant_signature.clone(),
                })
                .collect(),
            members: group.members.iter().map(|m| m.account_id.clone()).collect(),
        },
    );
    for m in &group.members {
        server.group_keys.push((
            m.account_id.clone(),
            GroupKeyRecord {
                group_id: group.id.clone(),
                key_version: 1,
                bundle: group.bundle.clone(),
                bundle_signature: group.bundle_signature.clone(),
                sealed_key: m.sealed_key.clone(),
                grant: m.grant.clone(),
                grant_signature: m.grant_signature.clone(),
            },
        ));
    }
    let report = alice.apply_sharing(server.delta(alice.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    let change = alice
        .share_vault(
            &vault_id,
            PrincipalType::Group,
            &group.id,
            VaultRole::View,
            22,
        )
        .unwrap();
    server.share(&vault_id, &change);
    let report = carol.apply_sharing(server.delta(carol.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert_eq!(report.view.vaults[0].role.as_deref(), Some("view"));
    assert!(carol.has_vault_key(&vault_id, 1));
    assert_eq!(report.view.orgs[0].groups[0].name.as_deref(), Some("Kids"));
    assert!(report.view.orgs[0].groups[0].members_verified);
    bob.apply_sharing(server.delta(bob.account_id()));

    // Remove Bob: rotate the vault key; Carol (via the group) and Alice get
    // epoch 2, Bob does not.
    alice.apply_sharing(server.delta(alice.account_id()));
    let rotation = alice
        .rotate_vault(
            &vault_id,
            &[(PrincipalType::Account, bob.account_id().to_owned())],
            r#"{"name":"Family"}"#,
            30,
        )
        .unwrap();
    assert_eq!(rotation.key_epoch, 2);
    assert_eq!(rotation.keys.len(), 2);
    server
        .vault_members
        .get_mut(&vault_id)
        .unwrap()
        .retain(|(_, id, _)| id != bob.account_id());
    server.access.insert(vault_id.clone(), (org_id.clone(), 2));
    server.add_manifest(&vault_id, &rotation.manifest, &rotation.manifest_signature);
    for key in &rotation.keys {
        server.add_vault_key(&vault_id, key);
    }
    let item = alice
        .encrypt_item_at(&vault_id, 2, "item1", 2, r#"{"title":"new"}"#)
        .unwrap();
    let report = carol.apply_sharing(server.delta(carol.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert!(carol.has_vault_key(&vault_id, 2));
    assert_eq!(
        carol
            .decrypt_item_at(&vault_id, 2, "item1", 2, &item)
            .unwrap(),
        r#"{"title":"new"}"#
    );
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(report.view.vaults.is_empty());
    assert!(!bob.has_vault_key(&vault_id, 2));

    // Group rotation without Carol: Alice keeps access, Carol's old group
    // key does not open the new version.
    alice.apply_sharing(server.delta(alice.account_id()));
    let rotated = alice
        .rotate_group(&group.id, &[carol.account_id().to_owned()], 40)
        .unwrap();
    assert_eq!(rotated.key_version, 2);
    assert_eq!(rotated.members.len(), 1);
}

#[test]
fn org_key_rotation_keeps_names_readable() {
    let (mut server, mut alice, mut bob, org_id, _vault) = family();
    let rotation = alice.rotate_org_key(&org_id, 50).unwrap();
    assert_eq!(rotation.epoch, 2);
    let record = server.orgs.get_mut(&org_id).unwrap();
    record.meta_epoch = 2;
    record.encrypted_meta = rotation.encrypted_meta.clone();
    for key in &rotation.keys {
        server.add_org_key(&org_id, key);
    }
    let report = bob.apply_sharing(server.delta(bob.account_id()));
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert_eq!(report.view.orgs[0].name.as_deref(), Some("Doe family"));
}

#[test]
fn signed_objects_have_stable_encodings() {
    // Guards against accidental format changes of signed objects.
    let manifest = VaultManifest {
        vault_id: "v".into(),
        org_id: "o".into(),
        version: 1,
        key_epoch: 1,
        members: vec![],
        prev_hash: [0; 32],
        signer_id: "a".into(),
        created_at: 0,
    };
    assert_eq!(
        encoding::encode(&crate::identity::object_hash(&manifest.to_canonical())),
        "a0cmRh4v9TJJMZexrDaLkZ3vOONmuEuO0hkr7_opIEc"
    );
}
