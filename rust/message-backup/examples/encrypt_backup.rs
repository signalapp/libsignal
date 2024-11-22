//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::io::{stdout, Read as _, Write};
use std::str::FromStr as _;

use aes::cipher::crypto_common::rand_core::{OsRng, RngCore};
use clap::builder::TypedValueParser;
use clap::{ArgAction, Parser};
use clap_stdin::FileOrStdin;
use libsignal_account_keys::{AccountEntropyPool, BackupKey};
use libsignal_core::Aci;
use libsignal_message_backup::args::{parse_aci, parse_hex_bytes};
use libsignal_message_backup::export::{
    aes_cbc_encrypt, gzip_compress, hmac_checksum, pad_gzipped_bucketed,
};
use libsignal_message_backup::key::MessageBackupKey;

const DEFAULT_ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
const DEFAULT_ACCOUNT_ENTROPY: &str =
    "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

#[derive(Parser)]
/// Compresses and encrypts an unencrypted backup file.
struct CliArgs {
    /// the file to read from, or '-' to read from stdin
    filename: FileOrStdin,

    /// the ACI to encrypt the backup file for
    #[arg(
        long,
        value_parser=parse_aci.map(WrapCliArg),
        default_value_t=WrapCliArg(DEFAULT_ACI)
    )]
    aci: WrapCliArg<Aci>,

    /// account entropy pool used (with the ACI) to derive the backup keys
    #[arg(long, conflicts_with = "master_key")]
    account_entropy: Option<String>,

    /// master key used (with the ACI) to derive the backup keys (deprecated)
    #[arg(long, conflicts_with="account_entropy", value_parser=parse_hex_bytes::<32>.map(WrapCliArg))]
    master_key: Option<WrapCliArg<[u8; BackupKey::MASTER_KEY_LEN]>>,

    #[arg(long, value_parser=parse_hex_bytes::<16>.map(WrapCliArg))]
    iv: Option<WrapCliArg<[u8; 16]>>,

    /// pad the compressed output to a bucket boundary before encrypting
    #[arg(long, default_value_t = true, action=ArgAction::Set)]
    pad_bucketed: bool,
}

fn main() {
    let CliArgs {
        filename,
        account_entropy,
        master_key,
        aci: WrapCliArg(aci),
        iv,
        pad_bucketed,
    } = CliArgs::parse();

    let key = match (account_entropy, master_key) {
        (Some(_), Some(_)) => unreachable!("enforced by clap"),
        (None, Some(WrapCliArg(master_key))) => {
            #[allow(deprecated)]
            let backup_key = BackupKey::derive_from_master_key(&master_key);
            let backup_id = backup_key.derive_backup_id(&aci);
            MessageBackupKey::derive(&backup_key, &backup_id)
        }
        (entropy_arg, None) => {
            let entropy_str = entropy_arg.as_deref().unwrap_or(DEFAULT_ACCOUNT_ENTROPY);
            let account_entropy =
                AccountEntropyPool::from_str(entropy_str).expect("valid account-entropy");
            let backup_key = BackupKey::derive_from_account_entropy_pool(&account_entropy);
            let backup_id = backup_key.derive_backup_id(&aci);
            MessageBackupKey::derive(&backup_key, &backup_id)
        }
    };

    let iv = iv.map(|WrapCliArg(iv)| iv).unwrap_or_else(|| {
        let mut iv = [0; 16];
        OsRng.fill_bytes(&mut iv);
        iv
    });

    eprintln!("reading from {:?}", filename.source);

    let contents = read_file(filename);
    eprintln!("read {} bytes", contents.len());

    let mut compressed_contents = gzip_compress(futures::io::Cursor::new(contents));
    eprintln!("compressed to {} bytes", compressed_contents.len());

    if pad_bucketed {
        pad_gzipped_bucketed(&mut compressed_contents);
        eprintln!("padded to {} bytes", compressed_contents.len());
    }

    let MessageBackupKey { hmac_key, aes_key } = &key;

    write_bytes("IV", iv);

    aes_cbc_encrypt(aes_key, &iv, &mut compressed_contents);
    eprintln!("encrypted to {} bytes", compressed_contents.len());

    let hmac = hmac_checksum(hmac_key, &iv, &compressed_contents);
    write_bytes("encrypted", compressed_contents);

    write_bytes("HMAC", hmac);
}

fn read_file(filename: FileOrStdin) -> Vec<u8> {
    let source = filename.source.clone();
    let mut contents = Vec::new();
    filename
        .into_reader()
        .unwrap_or_else(|e| panic!("failed to read {source:?}: {e}"))
        .read_to_end(&mut contents)
        .expect("IO error");
    contents
}

fn write_bytes(label: &'static str, bytes: impl AsRef<[u8]>) {
    let bytes = bytes.as_ref();
    stdout().write_all(bytes).expect("failed to write");
    eprintln!("wrote {} {label} bytes", bytes.len())
}

/// Wrapper struct to provide custom [`Display`] impls.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct WrapCliArg<T>(T);

impl Display for WrapCliArg<Aci> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.service_id_string())
    }
}

impl Display for WrapCliArg<[u8; 32]> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
