//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Key derivation from arguments, also shared with the examples.
//!
//! These *don't* live in the main library because they depend on clap.

use std::io::Read as _;
use std::str::FromStr as _;

use clap::Args;
use libsignal_account_keys::{AccountEntropyPool, BackupKey};
use libsignal_core::Aci;
use libsignal_message_backup::args::{parse_aci, parse_hex_bytes};
use libsignal_message_backup::frame::{CursorFactory, FileReaderFactory, ReaderFactory};
use libsignal_message_backup::key::MessageBackupKey;
use mediasan_common::SeekSkipAdapter;

// Only used for encrypt_backup/decrypt_backup, which need a default.
const DEFAULT_ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
const DEFAULT_ACCOUNT_ENTROPY: &str =
    "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

#[derive(Debug, Args, PartialEq)]
pub struct KeyArgs {
    // TODO once https://github.com/clap-rs/clap/issues/5092 is resolved, make
    // this `derive_key` and `key_parts` Optional at the top level.
    #[command(flatten)]
    pub derive_key: DeriveKey,
    #[command(flatten)]
    pub key_parts: KeyParts,
}

#[derive(Debug, Args, PartialEq)]
#[group(conflicts_with = "KeyParts")]
pub struct DeriveKey {
    /// account entropy pool, used with the ACI to derive the message backup key
    #[arg(long, conflicts_with = "master_key", requires = "aci")]
    pub account_entropy: Option<String>,
    /// master key used (with the ACI) to derive the backup keys (deprecated)
    #[arg(long, conflicts_with = "account_entropy", value_parser=parse_hex_bytes::<32>)]
    pub master_key: Option<[u8; BackupKey::MASTER_KEY_LEN]>,
    /// ACI for the backup creator
    #[arg(long, value_parser=parse_aci)]
    pub aci: Option<Aci>,
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
                master_key,
                aci,
            } = derive_key;
            aci.map(|aci| (aci, account_entropy, master_key))
        };
        let key_parts = {
            let KeyParts { hmac_key, aes_key } = key_parts;
            hmac_key.zip(aes_key)
        };

        match (derive_key, key_parts) {
            (None, None) => None,
            (None, Some((hmac_key, aes_key))) => Some(MessageBackupKey { aes_key, hmac_key }),
            (Some((_aci, None, None)), None) => {
                panic!("ACI provided, but no account-entropy or master-key")
            }
            (Some((aci, None, Some(master_key))), None) => Some({
                #[allow(deprecated)]
                let backup_key = BackupKey::derive_from_master_key(&master_key);
                let backup_id = backup_key.derive_backup_id(&aci);
                MessageBackupKey::derive(&backup_key, &backup_id)
            }),
            (Some((aci, Some(account_entropy), None)), None) => Some({
                let account_entropy =
                    AccountEntropyPool::from_str(&account_entropy).expect("valid account-entropy");
                let backup_key = BackupKey::derive_from_account_entropy_pool(&account_entropy);
                let backup_id = backup_key.derive_backup_id(&aci);
                MessageBackupKey::derive(&backup_key, &backup_id)
            }),
            (Some((_aci, Some(_), Some(_))), None) => {
                unreachable!("disallowed by clap arg parser")
            }
            (Some(_), Some(_)) => unreachable!("disallowed by clap arg parser"),
        }
    }

    #[allow(unused)] // only used from some targets
    pub fn into_key_or_default(self) -> MessageBackupKey {
        self.into_key().unwrap_or_else(|| {
            let account_entropy =
                AccountEntropyPool::from_str(DEFAULT_ACCOUNT_ENTROPY).expect("valid");
            let backup_key = BackupKey::derive_from_account_entropy_pool(&account_entropy);
            MessageBackupKey::derive(&backup_key, &backup_key.derive_backup_id(&DEFAULT_ACI))
        })
    }
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
