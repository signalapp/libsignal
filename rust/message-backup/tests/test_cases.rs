//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use dir_test::{dir_test, Fixture};
use futures::io::AllowStdIo;
use futures::AsyncRead;
use libsignal_message_backup::key::{BackupKey, MessageBackupKey};
use libsignal_message_backup::{BackupReader, ReadResult};
use libsignal_protocol::Aci;

#[dir_test(
        dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
        glob: "valid/*.binproto",
        loader: PathBuf::from,
        postfix: "binproto"
    )]
fn is_valid_binproto(input: Fixture<PathBuf>) {
    let path = input.into_content();
    // Check via the library interface.
    let reader = BackupReader::new_unencrypted(read_file_async(&path));
    validate(reader);

    // The CLI tool should agree.
    validator_command().arg(path).ok().expect("command failed");
}

#[dir_test(
        dir: "$CARGO_MANIFEST_DIR/tests/res/test-cases",
        glob: "valid/*.binproto.encrypted",
        loader: PathBuf::from,
        postfix: "encrypted"
    )]
fn is_valid_encrypted_proto(input: Fixture<PathBuf>) {
    const ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
    const MASTER_KEY: [u8; 32] = [b'M'; 32];
    let backup_key = BackupKey::derive_from_master_key(&MASTER_KEY);
    let key = MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&ACI));

    let path = input.into_content();
    // Check via the library interface.
    let reader = futures::executor::block_on(BackupReader::new_encrypted_compressed(
        &key,
        read_file_async(&path),
    ))
    .expect("invalid HMAC");
    validate(reader);

    // The CLI tool should agree.
    validator_command()
        .args([
            "--aci".to_string(),
            ACI.service_id_string(),
            "--master-key".to_string(),
            hex::encode(MASTER_KEY),
            path.to_string_lossy().into_owned(),
        ])
        .ok()
        .expect("command failed");
}

fn validate(mut reader: BackupReader<impl AsyncRead + Unpin>) {
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

fn read_file_async(path: &Path) -> AllowStdIo<std::fs::File> {
    let file = std::fs::File::open(path).expect("can read");
    AllowStdIo::new(file)
}
