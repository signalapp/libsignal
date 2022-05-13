//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! SGX quote, ported from Open Enclave headers in v0.17.7.

use std::convert::{TryFrom, TryInto};
use std::intrinsics::transmute;

use crate::dcap::sgx_report_body::SgxReportBody;
use crate::dcap::Error::Deserialization;
use crate::endian::*;

// Inline header file references are paths from the root of the repository tree.
// https://github.com/openenclave/openenclave/tree/v0.17.7

// sgx_quote.h
#[derive(Debug)]
pub(crate) struct SgxQuote<'a> {
    pub _quote_body: SgxQuoteBody,
    //    /* (436) signature array (varying length) */
    //    uint8_t signature[];
    pub signature: &'a [u8],
}

const DESERIALIZATION_NAME: &str = "SgxQuote";

impl<'a> SgxQuote<'a> {
    pub fn from_bytes(src: &'a [u8]) -> super::Result<Self> {
        if src.len() < std::mem::size_of::<SgxQuoteBody>() {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "incorrect buffer size",
            });
        }

        // check the version before we try to deserialize
        let version = u16::from_le_bytes(src[0..2].try_into().expect("correct size"));

        if version != 3 {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "unsupported quote version",
            });
        }

        let mut quote_body_bytes = [0u8; std::mem::size_of::<SgxQuoteBody>()];
        let (src, signature_bytes) = src.split_at(std::mem::size_of::<SgxQuoteBody>());
        quote_body_bytes.clone_from_slice(src);

        let quote_body = SgxQuoteBody::try_from(quote_body_bytes)?;

        if signature_bytes.len() < quote_body.signature_len.value() as usize {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "underflow reading signature",
            });
        }

        let signature = &signature_bytes[..quote_body.signature_len.value() as usize];

        Ok(SgxQuote {
            _quote_body: quote_body,
            signature,
        })
    }

    pub fn serialized_size(&self) -> usize {
        std::mem::size_of::<SgxQuoteBody>() + self.signature.len()
    }
}

#[derive(Debug)]
#[repr(C, packed)]
pub(crate) struct SgxQuoteBody {
    //    /* (0) */
    //    uint16_t version;
    pub version: UInt16LE,

    //    /* (2) */
    //    uint16_t sign_type;
    sign_type: UInt16LE,

    //    /* (4) */
    //    uint8_t reserved[4];
    reserved: [u8; 4],

    //    /* (8) */
    //    uint16_t qe_svn;
    qe_svn: UInt16LE,

    //    /* (10) */
    //    uint16_t pce_svn;
    pce_svn: UInt16LE,

    //    /* (12) */
    //    uint8_t uuid[16];
    uuid: [u8; 16],

    //    /* (28) */
    //    uint8_t user_data[20];
    user_data: [u8; 20],

    //    /* (48) */
    //    sgx_report_body_t report_body;
    report_body: SgxReportBody,

    //    /* (432) */
    //    uint32_t signature_len;
    signature_len: UInt32LE,
}

static_assertions::const_assert_eq!(436, std::mem::size_of::<SgxQuoteBody>());

impl TryFrom<[u8; std::mem::size_of::<SgxQuoteBody>()]> for SgxQuoteBody {
    type Error = super::Error;

    fn try_from(bytes: [u8; std::mem::size_of::<SgxQuoteBody>()]) -> super::Result<Self> {
        Ok(unsafe { transmute(bytes) })
    }
}
