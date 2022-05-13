//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! DCAP collateral (Open Enclave "endorsements"), ported from Open Enclave v0.17.7.
use std::convert::{TryFrom, TryInto};
use std::intrinsics::transmute;
use variant_count::VariantCount;

use crate::dcap::Error::Deserialization;
use crate::dcap::{Error, Result};
use crate::endian::UInt32LE;
use crate::util;

// Inline header file references are paths from the root of the repository tree.
// https://github.com/openenclave/openenclave/tree/v0.17.7

#[derive(Debug)]
/// Contains data to verify Evidence
pub(crate) struct Endorsements {
    // include/openenclave/bits/attestation.h
    // oe_endorsements_t
    _header: EndorsementsHeader,
    _endorsements: SgxEndorsements,
}

#[derive(Debug, VariantCount)]
#[repr(u8)]
enum SgxEndorsementField {
    Version = 0,
    TcbInfo,
    TcbIssuerChain,
    CrlPckCert,
    CrlPckProcCa,
    IssuerChainPckCert,
    QeIdInfo,
    QeIdIssuerChain,
    CreationDatetime,
}

#[derive(Debug)]
pub(crate) struct SgxEndorsements {
    // common/sgx/endorsements.h
    // oe_sgx_endorsements_t
    _version: u32,
    _tcb_info: String,
    _tcb_issuer_chain: String, // Future: Vec<Cert>
    _crl_pck_cert: String,
    _crl_pck_proc_ca: String,
    _issuer_chain_pck_cert: String, // Future: Vec<Cert>
    _qe_id_info: String,
    _qe_id_issuer_chain: String, // Future: Vec<Cert>
    _creation_datetime: String,
}

const DESERIALIZATION_NAME: &str = "endorsements";

impl TryFrom<&[u8]> for Endorsements {
    type Error = super::Error;

    fn try_from(mut src: &[u8]) -> super::Result<Self> {
        if src.len() < std::mem::size_of::<EndorsementsHeader>() {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "too short",
            });
        }

        let header_slice = util::read_bytes(&mut src, std::mem::size_of::<EndorsementsHeader>());
        let mut header_bytes = [0u8; std::mem::size_of::<EndorsementsHeader>()];
        header_bytes.clone_from_slice(header_slice);

        let header = EndorsementsHeader::try_from(header_bytes)?;

        let offsets_required_size =
            std::mem::size_of::<u32>() * (header.num_elements.value() as usize);
        if src.len() < offsets_required_size {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "not enough data for offsets",
            });
        }

        let (offsets, data) = src.split_at(offsets_required_size);

        let offsets = offsets
            .chunks_exact(4)
            .map(|d| u32::from_le_bytes(d.try_into().expect("correct size")) as usize)
            .collect::<Vec<usize>>();

        validate_offsets(&offsets, data)?;

        /*
         offsets are for each SGX endorsements field, in this order:

         include/openenclave/bits/attestation.h
         oe_sgx_endorsements_fields_t

           OE_SGX_ENDORSEMENT_FIELD_VERSION,
           OE_SGX_ENDORSEMENT_FIELD_TCB_INFO,
           OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN,
           OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT,
           OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA,
           OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT,
           OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO,
           OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN,
           OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME,

         Except for `version`, each field is a null-terminated string, including creation datetime, which
         is ISO 8601.
        */

        let endorsements = {
            let version_bytes = data_for_field(SgxEndorsementField::Version, &offsets, data);
            let version = u32::from_le_bytes(version_bytes.try_into().expect("correct size"));

            if version != 1 {
                return Err(Error::Deserialization {
                    name: DESERIALIZATION_NAME,
                    reason: "unsupported SGX endorsement version",
                });
            }

            let tcb_info = string_for_field(SgxEndorsementField::TcbInfo, &offsets, data)?;
            let tcb_issuer_chain =
                string_for_field(SgxEndorsementField::TcbIssuerChain, &offsets, data)?;
            let crl_pck_cert = string_for_field(SgxEndorsementField::CrlPckCert, &offsets, data)?;
            let crl_pck_proc_ca =
                string_for_field(SgxEndorsementField::CrlPckProcCa, &offsets, data)?;
            let issuer_chain_pck_cert =
                string_for_field(SgxEndorsementField::IssuerChainPckCert, &offsets, data)?;
            let qe_id_info = string_for_field(SgxEndorsementField::QeIdInfo, &offsets, data)?;
            let qe_id_issuer_chain =
                string_for_field(SgxEndorsementField::QeIdIssuerChain, &offsets, data)?;
            let creation_datetime =
                string_for_field(SgxEndorsementField::CreationDatetime, &offsets, data)?;

            SgxEndorsements {
                _version: version,
                _tcb_info: tcb_info,
                _tcb_issuer_chain: tcb_issuer_chain,
                _crl_pck_cert: crl_pck_cert,
                _crl_pck_proc_ca: crl_pck_proc_ca,
                _issuer_chain_pck_cert: issuer_chain_pck_cert,
                _qe_id_info: qe_id_info,
                _qe_id_issuer_chain: qe_id_issuer_chain,
                _creation_datetime: creation_datetime,
            }
        };

        Ok(Endorsements {
            _header: header,
            _endorsements: endorsements,
        })
    }
}

fn validate_offsets(offsets: &[usize], data: &[u8]) -> Result<()> {
    if offsets.len() < SgxEndorsementField::VARIANT_COUNT {
        return Err(Deserialization {
            name: DESERIALIZATION_NAME,
            reason: "too few fields",
        });
    }

    let last_offset = offsets.last().expect("cannot be empty");
    if data.len() <= *last_offset {
        return Err(Deserialization {
            name: DESERIALIZATION_NAME,
            reason: "data is too short for offsets",
        });
    }

    for (index, value) in offsets.iter().enumerate() {
        if index > 0 && *value <= *offsets.get(index - 1).unwrap() {
            return Err(Deserialization {
                name: DESERIALIZATION_NAME,
                reason: "offsets are not strictly increasing",
            });
        }
    }

    Ok(())
}

fn string_for_field(field: SgxEndorsementField, offsets: &[usize], data: &[u8]) -> Result<String> {
    let mut bytes = data_for_field(field, offsets, data);
    util::strip_trailing_null_byte(&mut bytes);

    String::from_utf8(Vec::from(bytes)).map_err(|_| Error::Deserialization {
        name: DESERIALIZATION_NAME,
        reason: "could not parse string",
    })
}

fn data_for_field<'a>(field: SgxEndorsementField, offsets: &[usize], data: &'a [u8]) -> &'a [u8] {
    // Safety note: `offsets` length, ordering, and `data` bounds checking are all done `validate_offsets`
    let index = field as usize;
    if index == offsets.len() - 1 {
        return &data[offsets[index]..];
    }
    &data[offsets[index]..offsets[index + 1]]
}

#[derive(Debug)]
#[repr(C, packed)]
pub(crate) struct EndorsementsHeader {
    // include/openenclave/bits/attestation.h
    // oe_endorsements_t
    // uint32_t version;      ///< Version of this structure
    version: UInt32LE,

    // uint32_t enclave_type; ///< The type of enclave (oe_enclave_type_t)
    enclave_type: UInt32LE,

    // uint32_t buffer_size;  ///< Size of the buffer
    buffer_size: UInt32LE,

    // uint32_t num_elements; ///< Number of elements stored in the data buffer
    num_elements: UInt32LE,
}

static_assertions::const_assert_eq!(16, std::mem::size_of::<EndorsementsHeader>());

impl TryFrom<[u8; std::mem::size_of::<EndorsementsHeader>()]> for EndorsementsHeader {
    type Error = super::Error;

    fn try_from(src: [u8; std::mem::size_of::<EndorsementsHeader>()]) -> super::Result<Self> {
        unsafe { Ok(transmute(src)) }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::{TryFrom, TryInto};
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn verify_signature_chain_integrity() {
        let _data = read_test_file("tests/data/dcap.endorsements");

        // let endorsements = Endorsements::from_bytes(data.as_slice());
    }

    #[test]
    fn make_endorsements() {
        let data = read_test_file("tests/data/dcap.endorsements");

        let endorsements =
            Endorsements::try_from(data.as_slice()).expect("failed to parse endorsements");

        assert_eq!(1, endorsements._endorsements._version)
    }

    #[test]
    fn make_endorsements_header() {
        let data: [u8; std::mem::size_of::<EndorsementsHeader>()] =
            read_test_file("tests/data/dcap.endorsements")
                [..std::mem::size_of::<EndorsementsHeader>()]
                .try_into()
                .unwrap();

        let header = EndorsementsHeader::try_from(data).expect("failed to parse header");

        assert_eq!(1, header.version.value());
        assert_eq!(2, header.enclave_type.value()) // oe_enclave_type_t (include/openenclave/bits/types.h)
    }

    fn read_test_file(path: &str) -> Vec<u8> {
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).expect("failed to read file")
    }
}
