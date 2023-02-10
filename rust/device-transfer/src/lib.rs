//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Support logic for Signal's device-to-device transfer feature.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::convert::TryInto;
use std::fmt;
use std::time::{Duration, SystemTime};

use boring::asn1::Asn1Time;
use boring::error::ErrorStack;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::x509::{X509Builder, X509Name, X509NameBuilder, X509};

/// Error types for device transfer.
#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Failure to decode some provided RSA private key.
    KeyDecodingFailed,
    /// Internal error in device transfer.
    InternalError(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::KeyDecodingFailed => write!(f, "Decoding provided RSA private key failed"),
            Error::InternalError(s) => write!(f, "Internal error in device transfer ({})", s),
        }
    }
}

/// Key serialization format.
#[derive(Copy, Clone, Debug)]
pub enum KeyFormat {
    /// DER-encoded PKCS8 PrivateKeyInfo format
    Pkcs8,
    /// DER-encoded key type specific format
    KeySpecific,
}

impl From<u8> for KeyFormat {
    fn from(value: u8) -> Self {
        match value {
            0u8 => KeyFormat::Pkcs8,
            _ => KeyFormat::KeySpecific,
        }
    }
}

/// Generate a private key of size `bits` and export to a specified format.
pub fn create_rsa_private_key(bits: usize, key_format: KeyFormat) -> Result<Vec<u8>, Error> {
    let rsa = Rsa::generate(bits as u32)
        .map_err(|_| Error::InternalError("RSA key generation failed"))?;
    let key =
        PKey::from_rsa(rsa).map_err(|_| Error::InternalError("Private key generation failed"))?;
    private_key_to_der(key, key_format)
}

fn private_key_to_der(key: PKey<Private>, format: KeyFormat) -> Result<Vec<u8>, Error> {
    match format {
        KeyFormat::KeySpecific => key
            .private_key_to_der()
            .map_err(|_| Error::InternalError("Exporting to a key specific format failed")),
        KeyFormat::Pkcs8 => key
            .private_key_to_der_pkcs8()
            .map_err(|_| Error::InternalError("Exporting to PKCS8 failed")),
    }
}

/// Generate a self-signed certificate of name `name`, expiring in `days_to_expire`.
///
/// `rsa_key_pkcs8` should be the output of [create_rsa_private_key].
pub fn create_self_signed_cert(
    rsa_key_pkcs8: &[u8],
    name: &str,
    days_to_expire: u32,
) -> Result<Vec<u8>, Error> {
    let rsa_key =
        PKey::private_key_from_der(rsa_key_pkcs8).map_err(|_| Error::KeyDecodingFailed)?;

    let valid_after_timestamp: libc::time_t = (SystemTime::now()
        - Duration::from_secs(60 * 60 * 24))
    .duration_since(SystemTime::UNIX_EPOCH)
    .map_err(|_| Error::InternalError("Could not generate valid start timestamp"))?
    .as_secs()
    .try_into()
    .map_err(|_| Error::InternalError("Could not generate valid start timestamp"))?;

    let cert = build_cert(rsa_key, name, valid_after_timestamp, days_to_expire)
        .map_err(|_| Error::InternalError("Creating certificate failed"))?;

    cert.to_der()
        .map_err(|_| Error::InternalError("Converting cert to DER failed"))
}

fn build_cert(
    rsa_key: PKey<Private>,
    name: &str,
    valid_after_timestamp: libc::time_t,
    days_to_expire: u32,
) -> Result<X509, ErrorStack> {
    let mut cert_builder = X509Builder::new()?;

    let issuer_name = build_self_signed_name(name)?;
    let subject_name = build_self_signed_name(name)?;
    cert_builder.set_issuer_name(&issuer_name)?;
    cert_builder.set_subject_name(&subject_name)?;

    let started_at = Asn1Time::from_unix(valid_after_timestamp)?;
    let ends_at = Asn1Time::days_from_now(days_to_expire)?;

    cert_builder.set_not_before(&started_at)?;
    cert_builder.set_not_after(&ends_at)?;

    cert_builder.set_pubkey(&rsa_key)?;
    cert_builder.sign(&rsa_key, MessageDigest::sha256())?;

    Ok(cert_builder.build())
}

fn build_self_signed_name(name: &str) -> Result<X509Name, ErrorStack> {
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", name)?;
    name_builder.append_entry_by_text("O", "Signal Foundation")?;
    name_builder.append_entry_by_text("OU", "Device Transfer")?;

    Ok(name_builder.build())
}
