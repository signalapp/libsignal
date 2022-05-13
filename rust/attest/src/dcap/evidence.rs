//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! DCAP quote (Open Enclave "evidence"), ported from Open Enclave headers in v0.17.7.

use std::collections::HashMap;
use std::convert::TryFrom;

use crate::dcap::sgx_quote::SgxQuote;
use crate::dcap::Error::Deserialization;
use crate::util;

// Inline header file references are paths from the root of the repository tree.
// https://github.com/openenclave/openenclave/tree/v0.17.7

#[derive(Debug)]
pub(crate) struct Evidence<'a> {
    pub _quote: SgxQuote<'a>,
    pub claims: HashMap<String, Vec<u8>>,
}

const DESERIALIZATION_NAME: &str = "evidence";

impl<'a> TryFrom<&'a [u8]> for Evidence<'a> {
    type Error = super::Error;

    fn try_from(bytes: &'a [u8]) -> super::Result<Self> {
        let quote = SgxQuote::from_bytes(bytes)?;

        let mut claims_bytes = &bytes[quote.serialized_size()..];

        // include/openenclave/attestation/custom_claims.h

        // oe_custom_claims_header_t
        //     uint64_t version;
        //     uint64_t num_claims;
        let custom_claims_version = util::read_u64_le(&mut claims_bytes);
        if custom_claims_version != 1 {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "unsupported claims version",
            });
        }

        let num_claims = util::read_u64_le(&mut claims_bytes);
        let mut claims = HashMap::with_capacity(num_claims as usize);

        for _ in 0..num_claims {
            // oe_custom_claims_entry_t
            //     uint64_t name_size;
            //     uint64_t value_size;
            //     uint8_t name[];
            //       // name_size bytes follow.
            //       // value_size_bytes follow.

            if claims_bytes.len() < 16 {
                return Err(Deserialization {
                    name: DESERIALIZATION_NAME,
                    reason: "underflow",
                });
            }

            let name_size = util::read_u64_le(&mut claims_bytes);
            let value_size = util::read_u64_le(&mut claims_bytes);

            if claims_bytes.len() < (name_size + value_size) as usize {
                return Err(Deserialization {
                    name: DESERIALIZATION_NAME,
                    reason: "underflow",
                });
            }

            let mut name_bytes = util::read_bytes(&mut claims_bytes, name_size as usize);
            util::strip_trailing_null_byte(&mut name_bytes);

            let name = String::from_utf8(Vec::from(name_bytes)).map_err(|_| Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "could not parse claims name to string",
            })?;

            let value = util::read_bytes(&mut claims_bytes, value_size as usize);

            claims.insert(name, Vec::from(value));
        }

        if !claims_bytes.is_empty() {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "unexpected extra data in buffer",
            });
        }

        Ok(Evidence {
            _quote: quote,
            claims,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use std::convert::TryFrom;
    use std::fs;
    use std::path::Path;

    const PUBKEY: [u8; 32] =
        hex!("2daeceddc174f3bdbf3ac02e250773e54a6d0eee3abe27acf2a277c34008c411");

    #[test]
    fn from_bytes() {
        let data = read_test_file("tests/data/dcap.evidence");

        let evidence = Evidence::try_from(data.as_slice()).expect("should parse");

        assert_eq!(PUBKEY, evidence.claims.get("pk").unwrap().as_slice());
        assert_eq!(3, evidence._quote._quote_body.version.value())
    }

    fn read_test_file(path: &str) -> Vec<u8> {
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).expect("failed to read file")
    }
}
