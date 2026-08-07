use encryptor::{
    decrypt_file, encrypt_file, export_public_key, generate_key_bundle, load_signing_identity,
    load_verification_key, DecryptOptions, EncryptOptions, Error, Password,
};
use std::fs;

fn password(value: &str) -> Password {
    Password::new(value.to_owned()).expect("valid password")
}

#[test]
fn encrypted_bundle_signs_and_verifies_streaming_envelope() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let bundle = directory.path().join("identity.ekey");
    let public = directory.path().join("identity.pub");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("signed.cpv2");
    let decrypted = directory.path().join("decrypted");
    fs::write(&input, vec![0x3c; 1_048_577]).expect("input");

    let _ = generate_key_bundle(&bundle, &password("key password")).expect("keygen");
    assert_eq!(fs::metadata(&bundle).expect("bundle metadata").len(), 144);
    let _ = export_public_key(&bundle, &public).expect("public export");
    let identity = load_signing_identity(&bundle, &password("key password")).expect("identity");
    let verification = load_verification_key(&public).expect("verification key");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("file password"),
        EncryptOptions::signed(&identity),
    )
    .expect("signed encryption");
    let _ = decrypt_file(
        &encrypted,
        &decrypted,
        &password("file password"),
        DecryptOptions::require_signature(&verification),
    )
    .expect("signed decryption");
    assert_eq!(
        fs::read(&decrypted).expect("decrypted"),
        vec![0x3c; 1_048_577]
    );
}

#[test]
fn signed_and_unsigned_policy_cannot_downgrade() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let bundle = directory.path().join("identity.ekey");
    let public = directory.path().join("identity.pub");
    let input = directory.path().join("plain");
    let signed = directory.path().join("signed");
    let unsigned = directory.path().join("unsigned");
    fs::write(&input, b"data").expect("input");
    let _ = generate_key_bundle(&bundle, &password("key password")).expect("keygen");
    let _ = export_public_key(&bundle, &public).expect("public export");
    let identity = load_signing_identity(&bundle, &password("key password")).expect("identity");
    let verification = load_verification_key(&public).expect("verification key");
    let _ = encrypt_file(
        &input,
        &signed,
        &password("file password"),
        EncryptOptions::signed(&identity),
    )
    .expect("signed encryption");
    let _ = encrypt_file(
        &input,
        &unsigned,
        &password("file password"),
        EncryptOptions::unsigned(),
    )
    .expect("unsigned encryption");

    assert!(decrypt_file(
        &signed,
        &directory.path().join("signed-out"),
        &password("file password"),
        DecryptOptions::unsigned(),
    )
    .is_err());
    assert!(decrypt_file(
        &unsigned,
        &directory.path().join("unsigned-out"),
        &password("file password"),
        DecryptOptions::require_signature(&verification),
    )
    .is_err());
}

#[test]
fn key_bundle_symlink_does_not_overwrite_victim() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary directory");
    let victim = directory.path().join("victim");
    let bundle = directory.path().join("identity.ekey");
    fs::write(&victim, b"preserve this").expect("victim");
    symlink(&victim, &bundle).expect("symlink");
    assert!(generate_key_bundle(&bundle, &password("password")).is_err());
    assert_eq!(fs::read(&victim).expect("victim after"), b"preserve this");
}

#[test]
fn wrong_key_password_is_collapsed_to_authentication_failure() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let bundle = directory.path().join("identity.ekey");
    let _ = generate_key_bundle(&bundle, &password("right password")).expect("keygen");
    assert!(matches!(
        load_signing_identity(&bundle, &password("wrong password")),
        Err(Error::AuthenticationFailure)
    ));
}

#[test]
fn output_modes_are_set_at_creation() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let bundle = directory.path().join("identity.ekey");
    let public = directory.path().join("identity.pub");
    let _ = generate_key_bundle(&bundle, &password("password")).expect("keygen");
    let _ = export_public_key(&bundle, &public).expect("public export");
    assert_eq!(
        fs::metadata(&bundle)
            .expect("bundle metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&public)
            .expect("public metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[test]
fn bad_signature_never_publishes_plaintext() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let bundle = directory.path().join("identity.ekey");
    let public = directory.path().join("identity.pub");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("signed");
    let output = directory.path().join("must-not-exist");
    fs::write(&input, vec![0x91; 1_048_577]).expect("input");
    let _ = generate_key_bundle(&bundle, &password("key password")).expect("keygen");
    let _ = export_public_key(&bundle, &public).expect("export");
    let identity = load_signing_identity(&bundle, &password("key password")).expect("identity");
    let verification = load_verification_key(&public).expect("verification key");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("file password"),
        EncryptOptions::signed(&identity),
    )
    .expect("signed encryption");
    let mut bytes = fs::read(&encrypted).expect("signed bytes");
    *bytes.last_mut().expect("signature byte") ^= 1;
    fs::write(&encrypted, bytes).expect("tampered signature");

    assert!(matches!(
        decrypt_file(
            &encrypted,
            &output,
            &password("file password"),
            DecryptOptions::require_signature(&verification),
        ),
        Err(Error::AuthenticationFailure)
    ));
    assert!(!output.exists());
    assert!(fs::read_dir(directory.path())
        .expect("directory")
        .filter_map(|entry| entry.ok())
        .all(|entry| !entry
            .file_name()
            .to_string_lossy()
            .starts_with(".encryptor-tmp-")));
}

#[test]
fn every_authenticated_key_bundle_region_rejects_tampering() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let bundle = directory.path().join("identity.ekey");
    let _ = generate_key_bundle(&bundle, &password("key password")).expect("keygen");
    let original = fs::read(&bundle).expect("bundle bytes");

    for (name, offset) in [
        ("salt", 24usize),
        ("nonce", 40usize),
        ("public", 52usize),
        ("seed", 96usize),
        ("tag", 128usize),
    ] {
        let changed_path = directory.path().join(format!("changed-{name}.ekey"));
        let mut changed = original.clone();
        changed[offset] ^= 1;
        fs::write(&changed_path, changed).expect("changed bundle");
        assert!(matches!(
            load_signing_identity(&changed_path, &password("key password")),
            Err(Error::AuthenticationFailure)
        ));
    }
}
