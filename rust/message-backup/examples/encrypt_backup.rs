//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::io::{stdout, Read as _, Write};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use async_compression::futures::bufread::GzipEncoder;
use clap::builder::TypedValueParser;
use clap::Parser;
use clap_stdin::FileOrStdin;
use futures::io::Cursor;
use futures::AsyncReadExt;
use hmac::Mac;
use libsignal_message_backup::args::{parse_aci, parse_hex_bytes};
use libsignal_message_backup::key::{BackupKey, MessageBackupKey};
use libsignal_protocol::Aci;
use sha2::Sha256;

const DEFAULT_ACI: Aci = Aci::from_uuid_bytes([0x11; 16]);
const DEFAULT_MASTER_KEY: [u8; 32] = [b'M'; 32];

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

    /// master key used (with the ACI) to derive the backup keys
    #[arg(
        long,
        value_parser=parse_hex_bytes::<32>.map(WrapCliArg),
        default_value_t=WrapCliArg(DEFAULT_MASTER_KEY)
    )]
    master_key: WrapCliArg<[u8; BackupKey::MASTER_KEY_LEN]>,
}

fn main() {
    let CliArgs {
        filename,
        master_key: WrapCliArg(master_key),
        aci: WrapCliArg(aci),
    } = CliArgs::parse();

    let backup_key = BackupKey::derive_from_master_key(&master_key);
    let backup_id = backup_key.derive_backup_id(&aci);
    let key = MessageBackupKey::derive(&backup_key, &backup_id);

    eprintln!("reading from {:?}", filename.source);

    let contents = read_file(filename);
    eprintln!("read {} bytes", contents.len());

    let compressed_contents = gzip_compress(contents);
    eprintln!("compressed to {} bytes", compressed_contents.len());

    let MessageBackupKey {
        hmac_key,
        aes_key,
        iv,
    } = &key;

    let encrypted_contents = aes_cbc_encrypt(aes_key, iv, compressed_contents);
    eprintln!("encrypted to {} bytes", encrypted_contents.len());

    let hmac = hmac_checksum(hmac_key, &encrypted_contents);
    write_bytes("encrypted", encrypted_contents);

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

fn aes_cbc_encrypt(aes_key: &[u8; 32], iv: &[u8; 16], compressed_contents: Vec<u8>) -> Vec<u8> {
    let encryptor = cbc::Encryptor::<Aes256>::new(aes_key.into(), iv.into());

    encryptor.encrypt_padded_vec_mut::<Pkcs7>(&compressed_contents)
}
fn hmac_checksum(hmac_key: &[u8; 32], encrypted_contents: &[u8]) -> [u8; 32] {
    let mut hmac = hmac::Hmac::<Sha256>::new_from_slice(hmac_key).expect("correct key size");
    hmac.update(encrypted_contents);
    hmac.finalize().into_bytes().into()
}

fn gzip_compress(contents: Vec<u8>) -> Vec<u8> {
    let mut compressed_contents = Vec::new();
    futures::executor::block_on(
        GzipEncoder::new(Cursor::new(contents)).read_to_end(&mut compressed_contents),
    )
    .expect("failed to compress");

    compressed_contents
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
        write!(f, "{}", hex::ToHex::encode_hex::<String>(&self.0))
    }
}
