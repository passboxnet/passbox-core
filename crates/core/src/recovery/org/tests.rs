use super::*;
use crate::sharing::objects::Signed;
use crate::sharing::tests::family;

fn record(upload: &OrgRecoveryKeyUpload) -> OrgRecoveryRecord {
    OrgRecoveryRecord {
        key_version: upload.key_version,
        bundle: upload.bundle.clone(),
        bundle_signature: upload.bundle_signature.clone(),
        grants: vec![RecoveryGrantRecord {
            account_id: upload.grant.account_id.clone(),
            key_version: upload.grant.key_version,
            grant: upload.grant.grant.clone(),
            grant_signature: upload.grant.grant_signature.clone(),
            sealed_key: Some(upload.grant.sealed_key.clone()),
        }],
    }
}

fn request(
    org_id: &str,
    account_id: &str,
    device: &RecoveryRequestKey,
    escrow: &RecoveryEscrowUpload,
) -> RecoveryRequestRecord {
    RecoveryRequestRecord {
        id: "req_1".into(),
        org_id: org_id.into(),
        account_id: account_id.into(),
        ephemeral_key: encoding::encode(&device.public_key()),
        key_version: escrow.key_version,
        escrow: escrow.escrow.clone(),
        escrow_signature: escrow.escrow_signature.clone(),
        sealed_key: escrow.sealed_key.clone(),
    }
}

fn approved(
    request: &RecoveryRequestRecord,
    approval: &RecoveryApprovalUpload,
    approver: &Keyring,
) -> ApprovedRecovery {
    let bundle = approver.own_bundle().unwrap();
    ApprovedRecovery {
        request_id: request.id.clone(),
        account_id: request.account_id.clone(),
        approval: approval.approval.clone(),
        approval_signature: approval.approval_signature.clone(),
        sealed_key: approval.sealed_key.clone(),
        approver_bundle: bundle.encoded(),
        approver_bundle_signature: bundle.encoded_signature(),
    }
}

#[test]
fn member_recovers_through_the_organization() {
    let (server, alice, mut bob, org_id, _) = family();
    bob.apply_sharing(server.delta(bob.account_id()));

    // Only owners and admins create the recovery key.
    assert!(bob.create_org_recovery_key(&org_id, 1, 20).is_err());
    let upload = alice.create_org_recovery_key(&org_id, 1, 20).unwrap();
    let record = record(&upload);

    let info = bob.verify_org_recovery(&org_id, &record).unwrap();
    assert_eq!(info.admins, vec![alice.account_id().to_owned()]);
    assert!(!info.can_approve);
    assert!(
        alice
            .verify_org_recovery(&org_id, &record)
            .unwrap()
            .can_approve
    );
    assert_eq!(info.fingerprint.split(' ').count(), 8);

    // Bob opts in.
    let escrow = bob.enroll_org_recovery(&org_id, &record, 21).unwrap();

    // Bob forgot his password: a new device asks for recovery.
    let device = RecoveryRequestKey::generate().unwrap();
    let code = device.request_code();
    assert_eq!(code.split(' ').count(), 4);
    let req = request(&org_id, bob.account_id(), &device, &escrow);

    // Alice approves after comparing the code.
    let approval = alice.approve_org_recovery(&record, &req, 22).unwrap();
    assert_eq!(approval.request_code, code);
    let recovered = device.open(&approved(&req, &approval, &alice)).unwrap();
    assert_eq!(recovered.account_id(), bob.account_id());
    assert_eq!(
        recovered.account_key().as_bytes(),
        bob.account_key().as_bytes()
    );

    // The persisted seed works the same.
    let restored = RecoveryRequestKey::from_seed(device.seed());
    assert!(restored.open(&approved(&req, &approval, &alice)).is_ok());

    // Members cannot approve.
    assert!(bob.approve_org_recovery(&record, &req, 23).is_err());
}

#[test]
fn a_swapped_ephemeral_key_or_forged_approval_fails() {
    let (server, alice, mut bob, org_id, _) = family();
    bob.apply_sharing(server.delta(bob.account_id()));
    let record = record(&alice.create_org_recovery_key(&org_id, 1, 20).unwrap());
    let escrow = bob.enroll_org_recovery(&org_id, &record, 21).unwrap();
    let device = RecoveryRequestKey::generate().unwrap();

    // A server that swaps in its own ephemeral key gets the approval, but
    // the code the admin compares differs, and the real device cannot open it.
    let server_key = RecoveryRequestKey::generate().unwrap();
    let swapped = request(&org_id, bob.account_id(), &server_key, &escrow);
    let approval = alice.approve_org_recovery(&record, &swapped, 22).unwrap();
    assert_ne!(approval.request_code, device.request_code());
    assert!(device.open(&approved(&swapped, &approval, &alice)).is_err());

    // A tampered sealed key or approval is rejected.
    let req = request(&org_id, bob.account_id(), &device, &escrow);
    let approval = alice.approve_org_recovery(&record, &req, 22).unwrap();
    let mut tampered = approved(&req, &approval, &alice);
    let mut sealed = encoding::decode(&tampered.sealed_key).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    tampered.sealed_key = encoding::encode(&sealed);
    assert!(device.open(&tampered).is_err());
    let mut wrong_signer = approved(&req, &approval, &alice);
    let bob_bundle = bob.own_bundle().unwrap();
    wrong_signer.approver_bundle = bob_bundle.encoded();
    wrong_signer.approver_bundle_signature = bob_bundle.encoded_signature();
    assert!(device.open(&wrong_signer).is_err());
    let mut other_request = approved(&req, &approval, &alice);
    other_request.request_id = "req_2".into();
    assert!(device.open(&other_request).is_err());
}

#[test]
fn forged_recovery_keys_and_escrows_are_rejected() {
    let (server, alice, mut bob, org_id, _) = family();
    bob.apply_sharing(server.delta(bob.account_id()));
    let genuine = record(&alice.create_org_recovery_key(&org_id, 1, 20).unwrap());

    // A recovery key signed by someone who is not an admin (here: a key the
    // server made up and signed with Bob's key) is not accepted.
    let forged_key = EncryptionKey::generate().unwrap();
    let forged = Signed::sign(
        RecoveryKeyBundle {
            org_id: org_id.clone(),
            key_version: 1,
            enc_pk: forged_key.public_key(),
            creator_id: bob.account_id().to_owned(),
            created_at: 20,
        },
        &bob.account_keys().unwrap().sig,
    );
    let forged_record = OrgRecoveryRecord {
        bundle: forged.encoded(),
        bundle_signature: forged.encoded_signature(),
        ..genuine.clone()
    };
    assert!(
        bob.enroll_org_recovery(&org_id, &forged_record, 21)
            .is_err()
    );
    assert!(bob.verify_org_recovery(&org_id, &forged_record).is_err());
    // A bundle for another organization or version is refused.
    let mut wrong_version = genuine.clone();
    wrong_version.key_version = 2;
    assert!(
        bob.enroll_org_recovery(&org_id, &wrong_version, 21)
            .is_err()
    );

    // An escrow signed by someone else does not verify for Bob.
    let escrow = bob.enroll_org_recovery(&org_id, &genuine, 21).unwrap();
    let alice_escrow = alice.enroll_org_recovery(&org_id, &genuine, 21).unwrap();
    let device = RecoveryRequestKey::generate().unwrap();
    let mut req = request(&org_id, bob.account_id(), &device, &escrow);
    req.escrow = alice_escrow.escrow.clone();
    req.escrow_signature = alice_escrow.escrow_signature.clone();
    req.sealed_key = alice_escrow.sealed_key.clone();
    assert!(alice.approve_org_recovery(&genuine, &req, 22).is_err());
    // A sealed key that the escrow does not cover is refused.
    let mut req = request(&org_id, bob.account_id(), &device, &escrow);
    req.sealed_key = alice_escrow.sealed_key;
    assert!(alice.approve_org_recovery(&genuine, &req, 22).is_err());

    // The recovery key can only be granted to verified admins.
    assert!(
        alice
            .grant_org_recovery(&org_id, &genuine, bob.account_id(), 23)
            .is_err()
    );
}
