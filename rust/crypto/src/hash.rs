//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{Error, Result};

use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

#[derive(Clone)]
pub enum CryptographicMac {
    HmacSha256(Hmac<Sha256>),
    HmacSha1(Hmac<Sha1>),
}

impl CryptographicMac {
    pub fn new(algo: &str, key: &[u8]) -> Result<Self> {
        match algo {
            "HMACSha1" | "HmacSha1" => Ok(Self::HmacSha1(
                Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            "HMACSha256" | "HmacSha256" => Ok(Self::HmacSha256(
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length"),
            )),
            _ => Err(Error::UnknownAlgorithm("MAC", algo.to_string())),
        }
    }

    pub fn update(&mut self, input: &[u8]) -> Result<()> {
        match self {
            Self::HmacSha1(sha1) => sha1.update(input),
            Self::HmacSha256(sha256) => sha256.update(input),
        }
        Ok(())
    }

    pub fn update_and_get(&mut self, input: &[u8]) -> Result<&mut Self> {
        self.update(input).map(|_| self)
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::HmacSha1(sha1) => sha1.finalize_reset().into_bytes().to_vec(),
            Self::HmacSha256(sha256) => sha256.finalize_reset().into_bytes().to_vec(),
        })
    }
}

#[derive(Clone)]
pub enum CryptographicHash {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl CryptographicHash {
    pub fn new(algo: &str) -> Result<Self> {
        match algo {
            "SHA-1" | "SHA1" | "Sha1" => Ok(Self::Sha1(Sha1::new())),
            "SHA-256" | "SHA256" | "Sha256" => Ok(Self::Sha256(Sha256::new())),
            "SHA-512" | "SHA512" | "Sha512" => Ok(Self::Sha512(Sha512::new())),
            _ => Err(Error::UnknownAlgorithm("digest", algo.to_string())),
        }
    }

    pub fn update(&mut self, input: &[u8]) -> Result<()> {
        match self {
            Self::Sha1(sha1) => sha1.update(input),
            Self::Sha256(sha256) => sha256.update(input),
            Self::Sha512(sha512) => sha512.update(input),
        }
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Sha1(sha1) => sha1.finalize_reset().to_vec(),
            Self::Sha256(sha256) => sha256.finalize_reset().to_vec(),
            Self::Sha512(sha512) => sha512.finalize_reset().to_vec(),
        })
    }
}
