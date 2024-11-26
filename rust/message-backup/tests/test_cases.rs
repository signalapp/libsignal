//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use assert_matches::assert_matches;
use dir_test::{dir_test, Fixture};
use futures::io::Cursor;
use futures::AsyncRead;
use libsignal_account_keys::BackupKey;
use libsignal_core::Aci;
use libsignal_message_backup::backup::Purpose;
use libsignal_message_backup::frame::{FileReaderFactory, VerifyHmac};
use libsignal_message_backup::key::MessageBackupKey;
use libsignal_message_backup::{BackupReader, ReadResult};

const BACKUP_PURPOSE: Purpose = Purpose::RemoteBackup;

const ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
const RAW_ACCOUNT_ENTROPY_POOL: &str =
    "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
const IV: [u8; 16] = [b'I'; 16];

#[dir_test(
        dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
        glob: "valid/*.jsonproto",
        postfix: "jsonproto"
    )]
fn is_valid_json_proto(input: Fixture<&str>) {
    let json_contents = input.into_content();
    let json_contents = json5::from_str(json_contents).expect("invalid JSON");
    let json_array = assert_matches!(json_contents, serde_json::Value::Array(contents) => contents);
    let binproto =
        libsignal_message_backup::backup::convert_from_json(json_array).expect("failed to convert");
    validate_proto(&binproto)
}

#[dir_test(
        dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
        glob: "valid/*.jsonproto",
        postfix: "serialize"
    )]
fn can_serialize_json_proto(input: Fixture<&str>) {
    let json_contents = input.into_content();
    let json_contents = json5::from_str(json_contents).expect("invalid JSON");
    let json_array = assert_matches!(json_contents, serde_json::Value::Array(contents) => contents);
    let binproto =
        libsignal_message_backup::backup::convert_from_json(json_array).expect("failed to convert");

    let input = Cursor::new(&binproto);
    let reader = BackupReader::new_unencrypted(input, BACKUP_PURPOSE);
    let result = futures::executor::block_on(reader.read_all())
        .result
        .expect("valid backup");
    // This should not crash.
    println!(
        "{}",
        libsignal_message_backup::backup::serialize::Backup::from(result).to_string_pretty()
    )
}

#[test]
fn serialized_account_settings_is_valid() {
    let binproto = include_bytes!("res/canonical-backup.binproto");
    let expected_canonical_str = include_str!("res/canonical-backup.expected.json");

    let input = Cursor::new(binproto);
    let reader = BackupReader::new_unencrypted(input, BACKUP_PURPOSE);
    let result = futures::executor::block_on(reader.read_all())
        .result
        .expect("valid backup");
    let canonical_repr =
        libsignal_message_backup::backup::serialize::Backup::from(result).to_string_pretty();
    pretty_assertions::assert_str_eq!(expected_canonical_str, canonical_repr)
}

#[test]
fn scrambler_smoke_test() {
    // Scrambling is deterministic, so we can check against expected output.
    let binproto = include_bytes!("res/canonical-backup.binproto");
    let scrambled_binproto = Command::cargo_bin("examples/scramble")
        .expect("bin exists")
        .arg("-")
        .write_stdin(binproto)
        .ok()
        .expect("valid binproto")
        .stdout;

    let input = Cursor::new(scrambled_binproto);
    let reader = BackupReader::new_unencrypted(input, BACKUP_PURPOSE);
    let result = futures::executor::block_on(reader.read_all())
        .result
        .expect("valid backup");
    let canonical_repr =
        libsignal_message_backup::backup::serialize::Backup::from(result).to_string_pretty();

    if write_expected_output() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/res/canonical-backup.scrambled.expected.json");
        eprintln!("writing expected contents to {:?}", path);
        std::fs::write(path, canonical_repr).expect("failed to overwrite expected contents");
        return;
    }

    let expected_canonical_str = include_str!("res/canonical-backup.scrambled.expected.json");
    pretty_assertions::assert_str_eq!(expected_canonical_str, canonical_repr)
}

const ENCRYPTED_SOURCE_SUFFIX: &str = ".source.jsonproto";
#[dir_test(
        dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
        glob: "valid-encrypted/*.binproto.encrypted",
        loader: PathBuf::from,
        postfix: "matches_source"
    )]
fn encrypted_proto_matches_source(input: Fixture<PathBuf>) {
    let path = input.into_content();
    let expected_source_path = format!("{}{ENCRYPTED_SOURCE_SUFFIX}", path.to_str().unwrap());

    let backup_key = BackupKey::derive_from_account_entropy_pool(
        &RAW_ACCOUNT_ENTROPY_POOL.parse().expect("valid"),
    );
    let key = MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&ACI));
    println!("hmac key: {}", hex::encode(key.hmac_key));
    println!("aes key: {}", hex::encode(key.aes_key));

    let source_as_binproto = Command::cargo_bin("examples/json_to_binproto")
        .expect("bin exists")
        .arg(expected_source_path)
        .ok()
        .expect("valid jsonproto")
        .stdout;

    let expected_contents = Command::cargo_bin("examples/encrypt_backup")
        .expect("bin exists")
        .args([
            "--aci",
            &ACI.service_id_string(),
            "--account-entropy",
            RAW_ACCOUNT_ENTROPY_POOL,
            "--iv",
            &hex::encode(IV),
            "-",
        ])
        .write_stdin(source_as_binproto)
        .ok()
        .expect("can encrypt")
        .stdout;

    if write_expected_output() {
        eprintln!("writing expected encrypted contents to {:?}", path);
        std::fs::write(path, expected_contents).expect("failed to overwrite expected contents");
        return;
    }

    let actual_contents = std::fs::read(&path).expect("can't load contents");

    assert_eq!(
        actual_contents, expected_contents,
        "file contents didn't match"
    );
}

#[dir_test(
        dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
        glob: "valid-encrypted/*.binproto.encrypted",
        loader: PathBuf::from,
        postfix: "encrypted"
    )]
fn is_valid_encrypted_proto(input: Fixture<PathBuf>) {
    let path = input.content();

    let backup_key = BackupKey::derive_from_account_entropy_pool(
        &RAW_ACCOUNT_ENTROPY_POOL.parse().expect("valid"),
    );
    let key = MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&ACI));
    println!("hmac key: {}", hex::encode(key.hmac_key));
    println!("aes key: {}", hex::encode(key.aes_key));

    // Check via the library interface.
    let factory = FileReaderFactory { path };
    let reader = futures::executor::block_on(BackupReader::new_encrypted_compressed(
        &key,
        factory,
        Purpose::RemoteBackup,
    ))
    .unwrap_or_else(|e| panic!("expected valid, got {e}"));
    validate(reader);

    // The CLI tool should agree.
    validator_command()
        .args([
            "--aci",
            &ACI.service_id_string(),
            "--account-entropy",
            RAW_ACCOUNT_ENTROPY_POOL,
            "--purpose",
            BACKUP_PURPOSE.into(),
            path.to_str().unwrap(),
        ])
        .ok()
        .expect("command failed");
}

const EXPECTED_SUFFIX: &str = "jsonproto.expected";
#[dir_test(
    dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
    glob: "invalid/*.jsonproto",
    loader: PathBuf::from
)]
fn invalid_jsonproto(input: Fixture<PathBuf>) {
    let path = input.into_content();
    let expected_path = path.with_extension(EXPECTED_SUFFIX);

    let json_contents = json5::from_str(&std::fs::read_to_string(path).expect("failed to read"))
        .expect("invalid JSON");
    let json_array = assert_matches!(json_contents, serde_json::Value::Array(contents) => contents);
    let binproto =
        libsignal_message_backup::backup::convert_from_json(json_array).expect("failed to convert");

    let input = Cursor::new(&*binproto);
    let reader = BackupReader::new_unencrypted(input, Purpose::RemoteBackup);

    let ReadResult {
        result,
        found_unknown_fields: _,
    } = futures::executor::block_on(reader.read_all());

    let text = result.expect_err("unexpectedly valid").to_string();

    if write_expected_output() {
        eprintln!("writing expected value to {:?}", expected_path);
        std::fs::write(expected_path, text).expect("failed to overwrite expected contents");
        return;
    }

    let expected_text =
        std::fs::read_to_string(&expected_path).expect("can't load expected contents");

    assert_eq!(text, expected_text);
}

fn write_expected_output() -> bool {
    std::env::var_os("OVERWRITE_EXPECTED_OUTPUT").is_some()
}

fn validate_proto(binproto: &[u8]) {
    // Check via the library interface.
    let input = Cursor::new(binproto);
    let reader = BackupReader::new_unencrypted(input, BACKUP_PURPOSE);
    validate(reader);

    // The CLI tool should agree.
    validator_command()
        .arg("-")
        .args(["--purpose", BACKUP_PURPOSE.into()])
        .write_stdin(binproto)
        .ok()
        .expect("command failed");
}

fn validate(mut reader: BackupReader<impl AsyncRead + Unpin + VerifyHmac>) {
    reader.visitor = |msg| println!("{msg:#?}");

    let ReadResult {
        result,
        found_unknown_fields,
    } = futures::executor::block_on(reader.read_all());
    assert_eq!(found_unknown_fields, Vec::new());

    let backup = result.expect("invalid backup");
    println!("got backup:\n{backup:#?}");
}

fn validator_command() -> Command {
    Command::cargo_bin("validator").expect("bin not found")
}
