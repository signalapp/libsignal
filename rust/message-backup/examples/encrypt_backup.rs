//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io::{stdout, Read as _, Write};

use aes::cipher::crypto_common::rand_core::{OsRng, RngCore};
use clap::{ArgAction, Parser};
use clap_stdin::FileOrStdin;
use libsignal_message_backup::args::parse_hex_bytes;
use libsignal_message_backup::export::{
    aes_cbc_encrypt, gzip_compress, hmac_checksum, pad_gzipped_bucketed,
};
use libsignal_message_backup::key::MessageBackupKey;

#[path = "../src/bin/support/mod.rs"]
mod support;
use support::KeyArgs;

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

    #[command(flatten)]
    key_args: KeyArgs,
}

fn main() {
    let CliArgs {
        input,
        iv,
        pad_bucketed,
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

fn read_file(input: FileOrStdin) -> Vec<u8> {
    let source = input.filename().to_owned();
    let mut contents = Vec::new();
    input
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
