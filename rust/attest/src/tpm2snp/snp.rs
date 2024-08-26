//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use boring_signal::bn::BigNum;
use boring_signal::ecdsa::EcdsaSig;
use boring_signal::pkey::{PKey, Public};
use boring_signal::rsa::Rsa;
use sha2::{Digest as _, Sha256, Sha384};
use subtle::ConstantTimeEq as _;

// Sizes and offsets are from the attestation_data definition:
// https://github.com/AMDESE/sev-guest/blob/bb790bd9d65ed1e4012d7bb2b45be90c6f567e03/include/attestation.h#L45
const SIG_PART_SIZE: usize = 48;
const SIG_PART_CAPACITY: usize = 72;
const REPORT_SIZE: usize = 1184;
const SIGNATURE_OFFSET: usize = 0x2A0;
const REPORT_DATA_OFFSET: usize = 0x50;
const SHA256_SIZE: usize = 32;

pub const ARK_GENOA_ROOT_PEM: &[u8] = include_bytes!("../../res/ark_genoa.pem");
pub const ARK_MILAN_ROOT_PEM: &[u8] = include_bytes!("../../res/ark_milan.pem");

#[allow(clippy::enum_variant_names)]
#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// Invalid SNP signature
    InvalidSignature,
    /// Invalid SNP report
    InvalidReport,
    /// Invalid runtime data
    InvalidRuntimeData,
    /// Invalid EC Key
    InvalidKey,
}
pub type Result<T> = std::result::Result<T, Error>;

pub struct Report<'a>(&'a [u8]);
pub struct RuntimeData<'a>(&'a [u8]);

impl<'a> Report<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != REPORT_SIZE {
            return Err(Error::InvalidReport);
        }

        Ok(Self(bytes))
    }

    pub fn verify(&self, public_key: PKey<Public>) -> Result<()> {
        let digest = Sha384::digest(self.data());
        let signature = self.signature();
        let ec_key = public_key.ec_key().map_err(|_| Error::InvalidKey)?;
        match signature.verify(digest.as_slice(), &ec_key) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(Error::InvalidSignature),
        }
    }

    fn digest(&self) -> &'a [u8] {
        &self.0[REPORT_DATA_OFFSET..][..SHA256_SIZE]
    }

    fn data(&self) -> &'a [u8] {
        &self.0[..SIGNATURE_OFFSET]
    }

    fn signature(&self) -> EcdsaSig {
        // Signature fields are stored in little endian,
        // but boring ECDSA implementation expects big endian.
        fn reversed(bytes: &[u8]) -> Vec<u8> {
            let mut bytes = bytes.to_vec();
            bytes.reverse();
            bytes
        }

        let signature_bytes = &self.0[SIGNATURE_OFFSET..];
        let r = reversed(&signature_bytes[..SIG_PART_SIZE]);
        let s = reversed(&signature_bytes[SIG_PART_CAPACITY..][..SIG_PART_SIZE]);
        let r = BigNum::from_slice(&r).expect("can extract r");
        let s = BigNum::from_slice(&s).expect("can extract s");
        EcdsaSig::from_private_components(r, s).expect("can initialize signature")
    }
}

impl<'a> RuntimeData<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        // Delay any verification.
        Ok(Self(bytes))
    }

    pub fn verify(&self, report: Report) -> Result<Rsa<Public>> {
        let digest = Sha256::digest(self.0);
        if !bool::from(digest.ct_eq(report.digest())) {
            return Err(Error::InvalidRuntimeData);
        }
        self.verify_json()
    }

    fn verify_json(&self) -> Result<Rsa<Public>> {
        let doc: RuntimeDocument =
            serde_json::from_slice(self.0).map_err(|_| Error::InvalidRuntimeData)?;
        let key = doc
            .keys
            .iter()
            .find(|entry| entry.kid == "HCLAkPub" && entry.kty == "RSA")
            .ok_or(Error::InvalidRuntimeData)?;

        fn to_big_num(b64: &str) -> Result<BigNum> {
            let raw = BASE64_URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|_| Error::InvalidRuntimeData)?;
            BigNum::from_slice(&raw).map_err(|_| Error::InvalidRuntimeData)
        }
        let n = to_big_num(key.n)?;
        let e = to_big_num(key.e)?;
        Rsa::from_public_components(n, e).map_err(|_| Error::InvalidRuntimeData)
    }
}

#[derive(serde::Deserialize, Debug)]
struct KeyEntry<'a> {
    kid: &'a str,
    e: &'a str,
    n: &'a str,
    kty: &'a str,
}

#[derive(serde::Deserialize, Debug)]
struct RuntimeDocument<'a> {
    #[serde(borrow)]
    keys: Vec<KeyEntry<'a>>,
}
