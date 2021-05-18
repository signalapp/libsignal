//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Support logic for Signal's device-to-device transfer feature.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use chrono::{Datelike, Duration, Utc};
use picky::key::PrivateKey;
use picky::x509::name::{DirectoryName, NameAttr};
use picky::x509::{certificate::CertificateBuilder, date::UTCDate};
use picky::{hash::HashAlgorithm, signature::SignatureAlgorithm};
use std::fmt;

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

/// Generate a private key of size `bits` and export to PKCS8 format.
pub fn create_rsa_private_key(bits: usize) -> Result<Vec<u8>, Error> {
    let key = PrivateKey::generate_rsa(bits)
        .map_err(|_| Error::InternalError("RSA key generation failed"))?;
    Ok(key
        .to_pkcs8()
        .map_err(|_| Error::InternalError("Exporting to PKCS8 failed"))?)
}

/// Generate a self-signed certificate of name `name`, expiring in `days_to_expire`.
///
/// `rsa_key_pkcs8` should be the output of [create_rsa_private_key].
pub fn create_self_signed_cert(
    rsa_key_pkcs8: &[u8],
    name: &str,
    days_to_expire: u32,
) -> Result<Vec<u8>, Error> {
    let rsa_key = PrivateKey::from_pkcs8(rsa_key_pkcs8).map_err(|_| Error::KeyDecodingFailed)?;

    let mut dn = DirectoryName::new_common_name(name);
    dn.add_attr(NameAttr::OrganizationName, "Signal Foundation");
    dn.add_attr(NameAttr::OrganizationalUnitName, "Device Transfer");

    let now = Utc::now();
    let expires = now + Duration::days(days_to_expire.into());

    let started_at = UTCDate::ymd(now.year() as u16, now.month() as u8, now.day() as u8)
        .ok_or(Error::InternalError("Cannot map current time to UTCDate"))?;
    let ends_at = UTCDate::ymd(
        expires.year() as u16,
        expires.month() as u8,
        expires.day() as u8,
    )
    .ok_or(Error::InternalError(
        "Cannot map expiration time to UTCDate",
    ))?;

    let cert = CertificateBuilder::new()
        .validity(started_at, ends_at)
        .self_signed(dn, &rsa_key)
        .signature_hash_type(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256))
        .build()
        .map_err(|_| Error::InternalError("Creating certificate failed"))?;

    Ok(cert
        .to_der()
        .map_err(|_| Error::InternalError("Converting cert to DER failed"))?)
}
