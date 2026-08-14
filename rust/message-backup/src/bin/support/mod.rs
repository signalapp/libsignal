//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(dead_code)]

//! Key derivation from arguments, also shared with the examples.
//!
//! These *don't* live in the main library because they depend on clap.

use std::io::Read as _;
use std::str::FromStr as _;

use clap::Args;
use clap_stdin::FileOrStdin;
use libsignal_account_keys::{AccountEntropyPool, BackupForwardSecrecyToken, BackupId, BackupKey};
use libsignal_cli_utils::read_file;
use libsignal_core::Aci;
use libsignal_message_backup::args::{parse_aci, parse_hex_bytes};
use libsignal_message_backup::frame::{CursorFactory, FileReaderFactory, ReaderFactory};
use libsignal_message_backup::key::MessageBackupKey;
use libsignal_message_backup::proto::LocalBackup::Metadata as LocalBackupMetadata;
use libsignal_message_backup::proto::LocalBackup::metadata::EncryptedBackupId;
use mediasan_common::SeekSkipAdapter;
use protobuf::Message as _;
use signal_crypto::Aes256Ctr32;

// Only used for encrypt_backup/decrypt_backup, which need a default.
const DEFAULT_ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
const DEFAULT_ACCOUNT_ENTROPY: &str =
    "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
const DEFAULT_BACKUP_FORWARD_SECRECY_TOKEN: BackupForwardSecrecyToken =
    BackupForwardSecrecyToken([0xAB; 32]);

#[derive(Debug, Args)]
pub struct KeyArgs {
    // TODO once https://github.com/clap-rs/clap/issues/5092 is resolved, make
    // this `derive_key` and `key_parts` Optional at the top level.
    #[command(flatten)]
    pub derive_key: DeriveKey,
    #[command(flatten)]
    pub key_parts: KeyParts,
}

#[derive(Debug, Args)]
#[group(conflicts_with = "KeyParts")]
pub struct DeriveKey {
    /// account entropy pool, used with the ACI or metadata file to derive the message backup key
    #[arg(long)]
    pub account_entropy: Option<String>,
    /// ACI for the backup creator
    #[arg(long, value_parser=parse_aci, requires = "account_entropy")]
    pub aci: Option<Aci>,
    /// backup metadata file
    #[arg(
        long = "metadata",
        requires = "account_entropy",
        conflicts_with = "aci"
    )]
    pub metadata_file: Option<FileOrStdin>,
    /// Backup forward secrecy token, used to derive the message backup key. May be absent.
    #[arg(long, value_parser=parse_hex_bytes::<32>)]
    pub forward_secrecy_token: Option<[u8; 32]>,
}

#[derive(Debug, Args, PartialEq)]
#[group(conflicts_with = "DeriveKey")]
pub struct KeyParts {
    /// HMAC key, used if the account entropy pool is not provided
    #[arg(long, value_parser=parse_hex_bytes::<32>, requires_all=["aes_key"])]
    pub hmac_key: Option<[u8; MessageBackupKey::HMAC_KEY_LEN]>,
    /// AES encryption key, used if the account entropy pool is not provided
    #[arg(long, value_parser=parse_hex_bytes::<32>, requires_all=["hmac_key"])]
    pub aes_key: Option<[u8; MessageBackupKey::AES_KEY_LEN]>,
}

impl KeyArgs {
    pub fn into_key(self) -> Option<MessageBackupKey> {
        let Self {
            derive_key,
            key_parts,
        } = self;

        let derive_key = {
            let DeriveKey {
                account_entropy,
                aci,
                metadata_file,
                forward_secrecy_token,
            } = derive_key;
            account_entropy.map(|aep| (aep, aci, metadata_file, forward_secrecy_token))
        };
        let key_parts = {
            let KeyParts { hmac_key, aes_key } = key_parts;
            hmac_key.zip(aes_key)
        };

        match (derive_key, key_parts) {
            (None, None) => None,
            (None, Some((hmac_key, aes_key))) => Some(MessageBackupKey { aes_key, hmac_key }),
            (Some((account_entropy, Some(aci), None, forward_secrecy_token)), None) => Some({
                let account_entropy =
                    parse_non_canonical_aep(&account_entropy).expect("valid account-entropy");
                let backup_key = BackupKey::derive_from_account_entropy_pool(&account_entropy);
                let backup_id = backup_key.derive_backup_id(&aci);
                let forward_secrecy_token = forward_secrecy_token.map(BackupForwardSecrecyToken);
                MessageBackupKey::derive(&backup_key, &backup_id, forward_secrecy_token.as_ref())
            }),
            (Some((account_entropy, None, Some(metadata_path), forward_secrecy_token)), None) => {
                Some({
                    let account_entropy =
                        parse_non_canonical_aep(&account_entropy).expect("valid account-entropy");
                    let backup_key = BackupKey::derive_from_account_entropy_pool(&account_entropy);
                    let local_backup_key = backup_key.derive_local_backup_metadata_key();
                    let metadata = read_file(metadata_path);
                    let backup_id = decode_metadata(&metadata, local_backup_key);
                    let forward_secrecy_token =
                        forward_secrecy_token.map(BackupForwardSecrecyToken);
                    MessageBackupKey::derive(
                        &backup_key,
                        &backup_id,
                        forward_secrecy_token.as_ref(),
                    )
                })
            }
            (Some((_, None, None, _)), None) => panic!("need ACI or metadata file to use AEP"),
            (Some((_, Some(_), Some(_), _)), None) => unreachable!("disallowed by clap arg parser"),
            (Some(_), Some(_)) => unreachable!("disallowed by clap arg parser"),
        }
    }

    #[allow(unused)] // only used from some targets
    pub fn into_key_or_default(self) -> MessageBackupKey {
        self.into_key().unwrap_or_else(|| {
            let account_entropy =
                AccountEntropyPool::from_str(DEFAULT_ACCOUNT_ENTROPY).expect("valid");
            let backup_key = BackupKey::derive_from_account_entropy_pool(&account_entropy);
            MessageBackupKey::derive(
                &backup_key,
                &backup_key.derive_backup_id(&DEFAULT_ACI),
                Some(&DEFAULT_BACKUP_FORWARD_SECRECY_TOKEN),
            )
        })
    }
}

fn parse_non_canonical_aep(
    input: &str,
) -> Result<AccountEntropyPool, libsignal_account_keys::InvalidAccountEntropyPool> {
    let mut input = input.replace(' ', "").replace('#', "o").replace('=', "0");
    input.make_ascii_lowercase();
    AccountEntropyPool::from_str(&input)
}

fn decode_metadata(file: &[u8], key: [u8; 32]) -> BackupId {
    let file_contents = LocalBackupMetadata::parse_from_bytes(file).expect("valid metadata file");
    let EncryptedBackupId {
        iv,
        encryptedId: mut raw_backup_id,
        special_fields: _,
    } = file_contents.backupId.unwrap_or_default();
    Aes256Ctr32::from_key(&key, &iv, 0)
        .expect("valid IV")
        .process(&mut raw_backup_id);
    BackupId(raw_backup_id.try_into().expect("valid backup ID"))
}

/// Filename or in-memory buffer of contents.
pub enum FilenameOrContents {
    Filename(String),
    Contents(Box<[u8]>),
}

impl From<clap_stdin::FileOrStdin> for FilenameOrContents {
    fn from(arg: clap_stdin::FileOrStdin) -> Self {
        if arg.is_stdin() {
            let mut buffer = vec![];
            std::io::stdin()
                .lock()
                .read_to_end(&mut buffer)
                .expect("failed to read from stdin");
            Self::Contents(buffer.into_boxed_slice())
        } else {
            Self::Filename(arg.filename().to_owned())
        }
    }
}

/// [`ReaderFactory`] impl backed by a [`FilenameOrContents`].
pub enum AsyncReaderFactory<'a> {
    // Using `AllowStdIo` with a `File` isn't generally a good idea since
    // the `Read` implementation will block. Since we're using a
    // single-threaded executor, though, the blocking I/O isn't a problem.
    // If that changes, this should be changed to an async-aware type, like
    // something from the `tokio` or `async-std` crates.
    File(FileReaderFactory<&'a str>),
    Cursor(CursorFactory<&'a [u8]>),
}

impl<'a> From<&'a FilenameOrContents> for AsyncReaderFactory<'a> {
    fn from(value: &'a FilenameOrContents) -> Self {
        match value {
            FilenameOrContents::Filename(path) => Self::File(FileReaderFactory { path }),
            FilenameOrContents::Contents(contents) => Self::Cursor(CursorFactory::new(contents)),
        }
    }
}

impl<'a> ReaderFactory for AsyncReaderFactory<'a> {
    type Reader = SeekSkipAdapter<
        futures::future::Either<
            futures::io::BufReader<futures::io::AllowStdIo<std::fs::File>>,
            <CursorFactory<&'a [u8]> as ReaderFactory>::Reader,
        >,
    >;

    fn make_reader(&mut self) -> futures::io::Result<Self::Reader> {
        match self {
            AsyncReaderFactory::File(f) => f.make_reader().map(|SeekSkipAdapter(f)| {
                futures::future::Either::Left(futures::io::BufReader::new(f))
            }),
            AsyncReaderFactory::Cursor(c) => c.make_reader().map(futures::future::Either::Right),
        }
        .map(SeekSkipAdapter)
    }
}
