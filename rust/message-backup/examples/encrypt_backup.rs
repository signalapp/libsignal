//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{Write as _, stdout};

use aes::cipher::crypto_common::rand_core::{OsRng, RngCore};
use clap::{ArgAction, Parser};
use clap_stdin::FileOrStdin;
use libsignal_cli_utils::read_file;
use libsignal_message_backup::args::parse_hex_bytes;
use libsignal_message_backup::export::{
    aes_cbc_encrypt, gzip_compress, hmac_checksum, pad_gzipped_bucketed,
};
use libsignal_message_backup::key::MessageBackupKey;
use libsignal_svrb::proto::Message as _;
use libsignal_svrb::proto::backup_metadata::{MetadataPb, metadata_pb};

#[path = "../src/bin/support/mod.rs"]
mod support;
use support::KeyArgs;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Format {
    Legacy,
    Modern,
}

#[derive(Parser)]
/// Compresses and encrypts an unencrypted backup file.
///
/// If no key is provided, the default testing key is assumed.
struct CliArgs {
    /// the file to read from, or '-' to read from stdin
    input: FileOrStdin,

    #[arg(long, value_parser=parse_hex_bytes::<16>)]
    iv: Option<[u8; 16]>,

    /// pad the compressed output to a bucket boundary before encrypting
    #[arg(long, default_value_t = true, action=ArgAction::Set)]
    pad_bucketed: bool,

    /// use the modern forward-secrecy format, or the legacy just-ciphertext format
    #[arg(long, default_value = "modern")]
    format: Format,

    /// ignore the all-ASCII input check
    #[arg(long, default_value_t = false)]
    force: bool,

    #[command(flatten)]
    key_args: KeyArgs,
}

fn main() {
    let CliArgs {
        input,
        iv,
        pad_bucketed,
        format,
        force,
        key_args,
    } = CliArgs::parse();

    let key = key_args.into_key_or_default();

    let iv = iv.unwrap_or_else(|| {
        let mut iv = [0; 16];
        OsRng.fill_bytes(&mut iv);
        iv
    });

    eprintln!("reading from {:?}", input.filename());

    let contents = read_file(input);
    eprintln!("read {} bytes", contents.len());

    if !force && contents.is_ascii() {
        eprintln!(
            "⚠️ encrypting a text file may not be what you want. Use --force if you mean it."
        );
        std::process::exit(-1);
    }

    let mut compressed_contents = gzip_compress(futures::io::Cursor::new(contents));
    eprintln!("compressed to {} bytes", compressed_contents.len());

    if pad_bucketed {
        pad_gzipped_bucketed(&mut compressed_contents);
        eprintln!("padded to {} bytes", compressed_contents.len());
    }

    if let Format::Modern = format {
        write_bytes(
            "magic number",
            libsignal_message_backup::frame::forward_secrecy::MAGIC_NUMBER,
        );
        let faux_metadata = MetadataPb {
            iv: b"iv_12_bytes_".to_vec(),
            pair: vec![metadata_pb::Pair {
                ct: [0xCC; 48].to_vec(),
                pw_salt: [0x50; 32].to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        write_bytes(
            "faux metadata",
            faux_metadata
                .write_length_delimited_to_bytes()
                .expect("can serialize"),
        );
    }

    let MessageBackupKey { hmac_key, aes_key } = &key;

    write_bytes("IV", iv);

    aes_cbc_encrypt(aes_key, &iv, &mut compressed_contents);
    eprintln!("encrypted to {} bytes", compressed_contents.len());

    let hmac = hmac_checksum(hmac_key, &iv, &compressed_contents);
    write_bytes("encrypted", compressed_contents);

    write_bytes("HMAC", hmac);
}

fn write_bytes(label: &'static str, bytes: impl AsRef<[u8]>) {
    let bytes = bytes.as_ref();
    stdout().write_all(bytes).expect("failed to write");
    eprintln!("wrote {} {label} bytes", bytes.len())
}
