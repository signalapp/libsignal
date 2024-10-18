//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! DCAP quote (Open Enclave "evidence"), ported from Open Enclave headers in v0.17.7.

use std::collections::HashMap;

use sha2::Digest;

use crate::dcap::sgx_quote::SgxQuote;
use crate::dcap::{Error, Expireable};
use crate::endian::UInt64LE;
use crate::error::Context;
use crate::util;

// Inline header file references are paths from the root of the repository tree.
// https://github.com/openenclave/openenclave/tree/v0.17.7

pub(crate) struct Evidence<'a> {
    pub quote: SgxQuote<'a>,
    pub claims: CustomClaims<'a>,
}

impl<'a> TryFrom<&'a [u8]> for Evidence<'a> {
    type Error = super::Error;

    /// Deserialize an `Evidence` from `bytes`
    ///
    /// bytes should contain an `SgxQuote` followed by
    /// custom claims. Any additional content in `bytes`
    /// is an error
    fn try_from(mut bytes: &'a [u8]) -> super::Result<Self> {
        let quote = SgxQuote::read(&mut bytes).context("quote")?;

        // bytes should now point at the start of custom_claims
        let claims: CustomClaims = bytes.try_into().context("claims")?;

        Ok(Evidence { quote, claims })
    }
}

impl Expireable for Evidence<'_> {
    fn valid_at(&self, timestamp: std::time::SystemTime) -> bool {
        self.quote.valid_at(timestamp)
    }
}

/// Version of oe_custom_claims_header_t/oe_custom_claims_entry_t
const OE_CLAIMS_V1: u64 = 1;

#[derive(Debug)]
pub(crate) struct CustomClaims<'a> {
    pub map: HashMap<String, Vec<u8>>,
    data: &'a [u8],
}

// include/openenclave/attestation/custom_claims.h
//
// oe_custom_claims_header_t
//     uint64_t version;
//     uint64_t num_claims;
#[derive(zerocopy::FromBytes, zerocopy::FromZeroes)]
#[repr(C)]
#[allow(dead_code)] // incorrectly identified as never constructed
struct CustomClaimsHeader {
    custom_claims_version: UInt64LE,
    num_claims: UInt64LE,
}
// oe_custom_claims_entry_t
//     uint64_t name_size;
//     uint64_t value_size;
//     uint8_t name[];
//       // name_size bytes follow.
//       // value_size_bytes follow.
#[derive(zerocopy::FromBytes, zerocopy::FromZeroes)]
#[repr(C)]
#[allow(dead_code)] // incorrectly identified as never constructed
struct CustomClaimsEntryHeader {
    name_size: UInt64LE,
    value_size: UInt64LE,
}

/// Deserializes an `OpenEnclave` custom claims struct (custom_claims.h)
impl<'a> TryFrom<&'a [u8]> for CustomClaims<'a> {
    type Error = super::Error;

    fn try_from(mut bytes: &'a [u8]) -> Result<Self, Self::Error> {
        // keep a reference to the original slice for later hashing
        let claims_data = bytes;

        let CustomClaimsHeader {
            custom_claims_version,
            num_claims,
        } = util::read_from_bytes(&mut bytes).ok_or_else(|| Error::new("underflow"))?;
        let num_claims = num_claims.get();

        if custom_claims_version.get() != OE_CLAIMS_V1 {
            return Err(Error::new("unsupported claims version"));
        }
        if num_claims > 256 {
            return Err(Error::new("too many custom claims"));
        }
        let num_claims = usize::try_from(num_claims).expect("just checked");
        let mut claims = HashMap::with_capacity(num_claims);

        for _ in 0..num_claims {
            let CustomClaimsEntryHeader {
                name_size,
                value_size,
            } = util::read_from_bytes(&mut bytes).ok_or_else(|| Error::new("underflow"))?;
            let name_size = name_size.get();
            let value_size = value_size.get();

            if name_size > 1024 {
                return Err(Error::new("custom claim name too long"));
            }
            let name_size = usize::try_from(name_size).expect("just checked");
            if value_size > 1024 * 1024 {
                return Err(Error::new("custom claim value too long"));
            }
            let value_size = usize::try_from(value_size).expect("just checked");

            if bytes.len() < (name_size + value_size) {
                return Err(Error::new("underflow"));
            }

            let mut name_bytes = util::read_bytes(&mut bytes, name_size);
            util::strip_trailing_null_byte(&mut name_bytes);

            let name = String::from_utf8(Vec::from(name_bytes))
                .map_err(|_| Error::new("could not parse claims name to string"))?;

            let value = util::read_bytes(&mut bytes, value_size);

            claims.insert(name, Vec::from(value));
        }

        if !bytes.is_empty() {
            return Err(Error::new("unexpected extra data in buffer"));
        }

        Ok(CustomClaims {
            map: claims,
            data: claims_data,
        })
    }
}

impl CustomClaims<'_> {
    pub fn data_sha256(&self) -> Vec<u8> {
        sha2::Sha256::digest(self.data).to_vec()
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use super::*;
    use crate::dcap::MREnclave;

    const EXPECTED_MRENCLAVE: MREnclave =
        hex!("337ac97ce088a132daeb1308ea3159f807de4a827e875b2c90ce21bf4751196f");

    #[test]
    fn from_bytes() {
        const DATA: &[u8] = include_bytes!("../../tests/data/dcap.evidence");
        let pkey = hex::decode(include_bytes!("../../tests/data/dcap.pubkey")).unwrap();

        let evidence = Evidence::try_from(DATA).expect("should parse");
        assert_eq!(pkey, evidence.claims.map.get("pk").unwrap().as_slice());
        assert_eq!(
            EXPECTED_MRENCLAVE,
            evidence.quote.quote_body.report_body.mrenclave
        )
    }

    fn test_claims() -> HashMap<String, Vec<u8>> {
        HashMap::from([
            ("first_claim".to_owned(), b"foo".to_vec()),
            ("SECOND CLAIM".to_owned(), b"bar".to_vec()),
            ("🥉 Claim".to_owned(), b"baz".to_vec()),
        ])
    }

    fn serialize(claims: &HashMap<String, Vec<u8>>) -> Vec<u8> {
        let version: [u8; 8] = 1u64.to_le_bytes();
        let num_claims: [u8; 8] = (claims.len() as u64).to_le_bytes();
        let mut buf: Vec<u8> = [version, num_claims].concat();
        for (name, v) in claims {
            let name_bytes: &[u8] = name.as_bytes();
            buf.extend((name_bytes.len() as u64).to_le_bytes());
            buf.extend((v.len() as u64).to_le_bytes());

            buf.extend(name_bytes);
            buf.extend(v);
        }
        buf
    }

    #[test]
    fn custom_claims() {
        let expected: HashMap<String, Vec<u8>> = test_claims();
        let serialized = serialize(&expected);
        let claims = CustomClaims::try_from(&*serialized).expect("should deserialize");
        assert_eq!(claims.map, expected);
    }

    #[test]
    fn null_terminated_claims() {
        let expected: HashMap<String, Vec<u8>> = test_claims();

        // add null terminators, will be lost on deserialize
        let nulled: HashMap<String, Vec<u8>> = expected
            .iter()
            .map(|(n, v)| {
                let mut n = n.to_owned();
                n.push('\0');
                (n, v.clone())
            })
            .collect();

        let serialized = serialize(&nulled);
        let claims = CustomClaims::try_from(&*serialized).expect("should deserialize");
        assert_eq!(claims.map, expected);
    }

    #[test]
    fn underflow_claims() {
        let version: [u8; 8] = 1u64.to_le_bytes();
        let num_claims: [u8; 8] = 1u64.to_le_bytes();
        let buf = [version, num_claims].concat();
        assert!(CustomClaims::try_from(&*buf).is_err());
    }

    #[test]
    fn empty_claims() {
        let buf = serialize(&HashMap::new());
        assert!(CustomClaims::try_from(&*buf).unwrap().map.is_empty())
    }
}
