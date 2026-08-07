use encryptor::{
    decrypt_file, encrypt_file, inspect_envelope, DecryptOptions, EncryptOptions, Error, Password,
};
use std::fs;

fn password(value: &str) -> Password {
    Password::new(value.to_owned()).expect("valid password")
}

#[test]
fn round_trips_empty_exact_and_multirecord_files() {
    for (name, data) in [
        ("empty", Vec::new()),
        ("small", b"authenticated streaming".to_vec()),
        ("exact", vec![0x5a; 1_048_576]),
        ("multi", vec![0xa5; 1_048_577]),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let input = directory.path().join(format!("{name}.plain"));
        let encrypted = directory.path().join(format!("{name}.cpv2"));
        let decrypted = directory.path().join(format!("{name}.out"));
        fs::write(&input, &data).expect("plaintext");
        let _ = encrypt_file(
            &input,
            &encrypted,
            &password("correct horse battery staple"),
            EncryptOptions::unsigned(),
        )
        .expect("encrypt");
        let metadata = inspect_envelope(&encrypted).expect("inspect");
        assert!(!metadata.is_signed());
        assert_eq!(metadata.plaintext_len(), data.len() as u64);
        let _ = decrypt_file(
            &encrypted,
            &decrypted,
            &password("correct horse battery staple"),
            DecryptOptions::unsigned(),
        )
        .expect("decrypt");
        assert_eq!(fs::read(&decrypted).expect("decrypted"), data);
    }
}

#[test]
fn existing_output_is_never_replaced() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let output = directory.path().join("existing");
    fs::write(&input, b"new value").expect("input");
    fs::write(&output, b"preserve me").expect("existing output");
    assert!(encrypt_file(
        &input,
        &output,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .is_err());
    assert_eq!(fs::read(&output).expect("preserved"), b"preserve me");
}

#[test]
fn tampered_final_tag_never_publishes_plaintext() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    let output = directory.path().join("must-not-exist");
    fs::write(&input, vec![0x41; 32 * 1024]).expect("input");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .expect("encrypt");
    let mut bytes = fs::read(&encrypted).expect("encrypted bytes");
    let last = bytes.last_mut().expect("tag byte");
    *last ^= 1;
    fs::write(&encrypted, bytes).expect("tampered input");

    let error = decrypt_file(
        &encrypted,
        &output,
        &password("password"),
        DecryptOptions::unsigned(),
    )
    .expect_err("tamper must fail");
    assert!(matches!(error, Error::AuthenticationFailure));
    assert!(!output.exists(), "final plaintext path was published");
    let residues: Vec<_> = fs::read_dir(directory.path())
        .expect("directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".encryptor-tmp-")
        })
        .collect();
    assert!(residues.is_empty(), "temporary plaintext residue remained");
}

#[test]
fn wrong_password_is_an_authentication_failure_without_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    let output = directory.path().join("output");
    fs::write(&input, b"secret").expect("input");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("right password"),
        EncryptOptions::unsigned(),
    )
    .expect("encrypt");
    assert!(matches!(
        decrypt_file(
            &encrypted,
            &output,
            &password("wrong password"),
            DecryptOptions::unsigned(),
        ),
        Err(Error::AuthenticationFailure)
    ));
    assert!(!output.exists());
}

#[test]
fn noncanonical_or_trailing_data_is_rejected_before_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    let output = directory.path().join("output");
    fs::write(&input, b"data").expect("input");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .expect("encrypt");
    let mut bytes = fs::read(&encrypted).expect("encrypted bytes");
    bytes.push(0);
    fs::write(&encrypted, bytes).expect("extended input");
    assert!(decrypt_file(
        &encrypted,
        &output,
        &password("password"),
        DecryptOptions::unsigned(),
    )
    .is_err());
    assert!(!output.exists());
}

#[test]
fn every_header_field_class_is_bound_or_rejected() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    fs::write(&input, b"header binding").expect("input");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .expect("encrypt");
    let original = fs::read(&encrypted).expect("encrypted bytes");

    for offset in [0usize, 4, 5, 6, 7, 8, 9, 10, 12, 16, 20, 24, 28, 60] {
        let mut changed = original.clone();
        changed[offset] ^= 0x80;
        assert!(
            encryptor::validate_envelope_structure(&changed).is_err(),
            "structural field at byte {offset} was accepted"
        );
    }

    for (name, offset) in [("salt", 36usize), ("nonce", 52usize)] {
        let changed_path = directory.path().join(format!("changed-{name}"));
        let output = directory.path().join(format!("output-{name}"));
        let mut changed = original.clone();
        changed[offset] ^= 1;
        fs::write(&changed_path, changed).expect("changed envelope");
        assert!(matches!(
            decrypt_file(
                &changed_path,
                &output,
                &password("password"),
                DecryptOptions::unsigned(),
            ),
            Err(Error::AuthenticationFailure)
        ));
        assert!(!output.exists());
    }
}

#[test]
fn record_state_machine_rejects_reordering_missing_finality_and_splicing() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    fs::write(&input, vec![0x5c; 1_048_577]).expect("input");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .expect("encrypt");
    let original = fs::read(&encrypted).expect("encrypted bytes");
    let first_start = 64usize;
    let first_end = first_start + 12 + 1_048_576 + 16;

    let mut missing_final = original.clone();
    missing_final[first_end + 8] = 0;
    assert!(encryptor::validate_envelope_structure(&missing_final).is_err());

    let mut duplicate_final = original.clone();
    duplicate_final[first_start + 8] = 1;
    assert!(encryptor::validate_envelope_structure(&duplicate_final).is_err());

    let mut incorrect_length = original.clone();
    incorrect_length[first_start + 4..first_start + 8]
        .copy_from_slice(&(1_048_575u32).to_le_bytes());
    assert!(encryptor::validate_envelope_structure(&incorrect_length).is_err());

    let mut unknown_flags = original.clone();
    unknown_flags[first_start + 8] |= 0x80;
    assert!(encryptor::validate_envelope_structure(&unknown_flags).is_err());

    let mut nonzero_reserved = original.clone();
    nonzero_reserved[first_start + 9] = 1;
    assert!(encryptor::validate_envelope_structure(&nonzero_reserved).is_err());

    let mut skipped_index = original.clone();
    skipped_index[first_end..first_end + 4].copy_from_slice(&2u32.to_le_bytes());
    assert!(encryptor::validate_envelope_structure(&skipped_index).is_err());

    let mut reordered = Vec::with_capacity(original.len());
    reordered.extend_from_slice(&original[..first_start]);
    reordered.extend_from_slice(&original[first_end..]);
    reordered.extend_from_slice(&original[first_start..first_end]);
    assert!(encryptor::validate_envelope_structure(&reordered).is_err());

    let mut duplicated = original.clone();
    duplicated.extend_from_slice(&original[first_start..first_end]);
    assert!(encryptor::validate_envelope_structure(&duplicated).is_err());

    let truncated = &original[..original.len() - 1];
    assert!(encryptor::validate_envelope_structure(truncated).is_err());
}

#[test]
fn truncated_reordered_and_late_spliced_inputs_never_publish() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let other_input = directory.path().join("other-plain");
    let encrypted = directory.path().join("encrypted");
    let other_encrypted = directory.path().join("other-encrypted");
    fs::write(&input, vec![0x5c; 1_048_577]).expect("input");
    fs::write(&other_input, vec![0xa7; 1_048_577]).expect("other input");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .expect("encrypt");
    let _ = encrypt_file(
        &other_input,
        &other_encrypted,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .expect("other encrypt");
    let original = fs::read(&encrypted).expect("encrypted bytes");
    let other = fs::read(&other_encrypted).expect("other encrypted bytes");
    let first_start = 64usize;
    let second_start = first_start + 12 + 1_048_576 + 16;

    let mut reordered = Vec::with_capacity(original.len());
    reordered.extend_from_slice(&original[..first_start]);
    reordered.extend_from_slice(&original[second_start..]);
    reordered.extend_from_slice(&original[first_start..second_start]);

    let mut spliced = original.clone();
    spliced[second_start + 12..].copy_from_slice(&other[second_start + 12..]);

    for (name, changed) in [
        ("truncated", original[..original.len() - 1].to_vec()),
        ("reordered", reordered),
        ("late-spliced", spliced),
    ] {
        let changed_path = directory.path().join(format!("{name}.cpv2"));
        let output = directory.path().join(format!("{name}.out"));
        fs::write(&changed_path, changed).expect("changed input");
        assert!(decrypt_file(
            &changed_path,
            &output,
            &password("password"),
            DecryptOptions::unsigned(),
        )
        .is_err());
        assert!(!output.exists(), "{name} input published plaintext");
        assert!(fs::read_dir(directory.path())
            .expect("directory")
            .filter_map(|entry| entry.ok())
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".encryptor-tmp-")));
    }
}

#[test]
fn private_outputs_and_symlink_victims_are_preserved() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempfile::tempdir().expect("temporary directory");
    let input = directory.path().join("plain");
    let encrypted = directory.path().join("encrypted");
    let recovered = directory.path().join("recovered");
    fs::write(&input, b"private mode").expect("input");
    let _ = encrypt_file(
        &input,
        &encrypted,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .expect("encrypt");
    let _ = decrypt_file(
        &encrypted,
        &recovered,
        &password("password"),
        DecryptOptions::unsigned(),
    )
    .expect("decrypt");
    for path in [&encrypted, &recovered] {
        assert_eq!(
            fs::metadata(path)
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let victim = directory.path().join("victim");
    let symlink_output = directory.path().join("symlink-output");
    fs::write(&victim, b"preserve me").expect("victim");
    symlink(&victim, &symlink_output).expect("output symlink");
    assert!(encrypt_file(
        &input,
        &symlink_output,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .is_err());
    assert_eq!(fs::read(&victim).expect("preserved victim"), b"preserve me");

    let symlink_input = directory.path().join("symlink-input");
    let rejected_output = directory.path().join("rejected-output");
    symlink(&input, &symlink_input).expect("input symlink");
    assert!(encrypt_file(
        &symlink_input,
        &rejected_output,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .is_err());
    assert!(!rejected_output.exists());
}

#[test]
fn source_equals_output_and_oversized_sparse_input_fail_before_publication() {
    use std::fs::OpenOptions;

    let directory = tempfile::tempdir().expect("temporary directory");
    let source = directory.path().join("source");
    fs::write(&source, b"must remain unchanged").expect("source");
    assert!(encrypt_file(
        &source,
        &source,
        &password("password"),
        EncryptOptions::unsigned(),
    )
    .is_err());
    assert_eq!(
        fs::read(&source).expect("preserved source"),
        b"must remain unchanged"
    );

    let sparse = directory.path().join("oversized-sparse");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sparse)
        .expect("sparse file");
    if file.set_len((1u64 << 52) + 1).is_err() {
        // Common Linux filesystems cap sparse files below the CPV2 2^52-byte
        // limit. The pure boundary arithmetic is covered independently.
        return;
    }
    drop(file);
    let output = directory.path().join("oversized-output");
    assert!(matches!(
        encrypt_file(
            &sparse,
            &output,
            &password("password"),
            EncryptOptions::unsigned(),
        ),
        Err(Error::LimitExceeded(_))
    ));
    assert!(!output.exists());
}
