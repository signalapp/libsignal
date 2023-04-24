//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! DCAP collateral (Open Enclave "endorsements"), ported from Open Enclave v0.17.7.
//! The collateral packed collateral from OE is typically fetched by the enclave being attested
//! through the Intel Provisioning Certification Service (PCS), or a cache (PCCS).
//! For specification of the json data structures within the OE structures,
//! see <https://api.portal.trustedservices.intel.com/documentation>
use boring::ec::EcKeyRef;
use boring::ecdsa::{EcdsaSig, EcdsaSigRef};
use boring::pkey::Public;
use chrono::Utc;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::convert::{TryFrom, TryInto};
use std::intrinsics::transmute;
use std::time::SystemTime;
use variant_count::VariantCount;

use crate::dcap::cert_chain::CertChain;
use crate::dcap::ecdsa::{deserialize_ecdsa_signature, EcdsaSigned};
use crate::dcap::revocation_list::RevocationList;
use crate::dcap::{Error, Expireable, Result};
use crate::endian::UInt32LE;
use crate::error::Context;
use crate::util;

// Inline header file references are paths from the root of the repository tree.
// https://github.com/openenclave/openenclave/tree/v0.17.7

#[derive(Debug, Clone, Copy, VariantCount)]
#[repr(u8)]
enum SgxEndorsementField {
    Version = 0,
    TcbInfo,
    TcbIssuerChain,
    CrlPckCert,
    CrlPckProcCa,
    PckCrlIssuerChain,
    QeIdInfo,
    QeIdIssuerChain,
    CreationDatetime,
}

/// The version of the oe_sgx_endorsements_t
/// struct that we're parsing
const OE_ENDORSEMENTS_V1: u32 = 1;

/// Contains data to verify Evidence
pub(crate) struct SgxEndorsements {
    // common/sgx/endorsements.h
    // oe_sgx_endorsements_t
    _version: u32,
    pub tcb_info: TcbInfo,
    pub tcb_issuer_chain: CertChain,

    /// The CRL for the pck issuer
    pub pck_issuer_crl: RevocationList,

    /// The CRL for the root of pck chain (which is
    /// the intel root CA). In OE this is
    /// OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA
    /// which is extra confusing because the processor
    /// and platform certificate chains are distinct
    /// (but have the same root!)
    pub root_crl: RevocationList,

    /// The certificate chain whose leaf issues the
    /// pck_issuer_crl
    pub pck_issuer_crl_chain: CertChain,

    pub qe_id_info: EnclaveIdentity,
    pub qe_id_issuer_chain: CertChain,

    /// this isn't trusted data, so we can ignore it
    _creation_datetime: String,
}

impl TryFrom<&[u8]> for SgxEndorsements {
    type Error = Error;

    fn try_from(mut src: &[u8]) -> super::Result<Self> {
        if src.len() < std::mem::size_of::<EndorsementsHeader>() {
            return Err(Error::new("too short"));
        }

        let header_slice = util::read_bytes(&mut src, std::mem::size_of::<EndorsementsHeader>());
        let mut header_bytes = [0u8; std::mem::size_of::<EndorsementsHeader>()];
        header_bytes.copy_from_slice(header_slice);

        let header = EndorsementsHeader::try_from(header_bytes)?;

        if header.version.value() != 1 {
            return Err(Error::new(format!(
                "unsupported endorsements version {}",
                header.version.value()
            )));
        }

        if header.enclave_type.value() != 2 {
            return Err(Error::new(format!(
                "unsupported enclave type {}",
                header.enclave_type.value()
            )));
        }

        let offsets_required_size =
            std::mem::size_of::<u32>() * (header.num_elements.value() as usize);
        if src.len() < offsets_required_size {
            return Err(Error::new("not enough data for offsets"));
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

        let version_bytes = data_for_field(SgxEndorsementField::Version, &offsets, data);
        let version = u32::from_le_bytes(
            version_bytes
                .try_into()
                .map_err(|_| Error::new("invalid SGX endorsement version field"))?,
        );

        if version != OE_ENDORSEMENTS_V1 {
            return Err(Error::new(format!(
                "unsupported SGX endorsement version {}",
                version
            )));
        }

        let mut tcb_info = data_for_field(SgxEndorsementField::TcbInfo, &offsets, data);
        util::strip_trailing_null_byte(&mut tcb_info);
        let tcb_info: TcbInfoAndSignature =
            serde_json::from_slice(tcb_info).map_err(|e| Error::from(e).context("tcb info"))?;
        let tcb_issuer_chain =
            pem_chain_for_field(SgxEndorsementField::TcbIssuerChain, &offsets, data)?;
        let pck_issuer_crl = der_crl_for_field(SgxEndorsementField::CrlPckCert, &offsets, data)?;
        let root_crl = der_crl_for_field(SgxEndorsementField::CrlPckProcCa, &offsets, data)?;
        let pck_issuer_crl_chain =
            pem_chain_for_field(SgxEndorsementField::PckCrlIssuerChain, &offsets, data)?;

        let tcb_info = tcb_info.into_tcb_info(
            &*tcb_issuer_chain
                .leaf_pub_key()
                .context("tcb issuer chain")?,
        )?;
        let mut qe_id_info = data_for_field(SgxEndorsementField::QeIdInfo, &offsets, data);
        util::strip_trailing_null_byte(&mut qe_id_info);
        let qe_id_info: QuotingEnclaveIdentityAndSignature = serde_json::from_slice(qe_id_info)
            .map_err(|e| Error::from(e).context("quoting enclave identity info"))?;
        let qe_id_issuer_chain =
            pem_chain_for_field(SgxEndorsementField::QeIdIssuerChain, &offsets, data)?;
        let qe_id_info = qe_id_info.into_enclave_identity(
            &*qe_id_issuer_chain
                .leaf_pub_key()
                .context("qe identity issuer chain")?,
        )?;

        let creation_datetime =
            string_for_field(SgxEndorsementField::CreationDatetime, &offsets, data)?;

        Ok(SgxEndorsements {
            _version: version,
            tcb_info,
            tcb_issuer_chain,
            pck_issuer_crl,
            root_crl,
            pck_issuer_crl_chain,
            qe_id_info,
            qe_id_issuer_chain,
            _creation_datetime: creation_datetime,
        })
    }
}

impl Expireable for SgxEndorsements {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.qe_id_issuer_chain.valid_at(timestamp)
            && self.pck_issuer_crl_chain.valid_at(timestamp)
            && self.tcb_issuer_chain.valid_at(timestamp)
            && self.tcb_info.valid_at(timestamp)
            && self.qe_id_info.valid_at(timestamp)
            && self.pck_issuer_crl.valid_at(timestamp)
            && self.root_crl.valid_at(timestamp)
    }
}

fn validate_offsets(offsets: &[usize], data: &[u8]) -> Result<()> {
    if offsets.len() < SgxEndorsementField::VARIANT_COUNT {
        return Err(Error::new("too few fields"));
    }

    let last_offset = offsets.last().expect("cannot be empty");
    if data.len() <= *last_offset {
        return Err(Error::new("data is too short for offsets"));
    }

    for (index, value) in offsets.iter().enumerate() {
        if index > 0 && *value <= offsets[index - 1] {
            return Err(Error::new("offsets are not strictly increasing"));
        }
    }

    Ok(())
}

fn pem_chain_for_field(
    field: SgxEndorsementField,
    offsets: &[usize],
    data: &[u8],
) -> Result<CertChain> {
    let data = data_for_field(field, offsets, data);

    CertChain::from_pem_data(data).with_context(|| format!("{:?}", &field))
}

fn der_crl_for_field(
    field: SgxEndorsementField,
    offsets: &[usize],
    data: &[u8],
) -> Result<RevocationList> {
    let data = data_for_field(field, offsets, data);

    RevocationList::from_der_data(data).with_context(|| format!("{:?}", field))
}

fn string_for_field(field: SgxEndorsementField, offsets: &[usize], data: &[u8]) -> Result<String> {
    let mut bytes = data_for_field(field, offsets, data);
    util::strip_trailing_null_byte(&mut bytes);

    String::from_utf8(Vec::from(bytes)).map_err(|e| Error::from(e).context(format!("{:?}", field)))
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
#[repr(C)]
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

static_assertions::const_assert_eq!(1, std::mem::align_of::<EndorsementsHeader>());
static_assertions::const_assert_eq!(16, std::mem::size_of::<EndorsementsHeader>());

impl TryFrom<[u8; std::mem::size_of::<EndorsementsHeader>()]> for EndorsementsHeader {
    type Error = super::Error;

    fn try_from(src: [u8; std::mem::size_of::<EndorsementsHeader>()]) -> super::Result<Self> {
        unsafe { Ok(transmute(src)) }
    }
}

#[cfg(test)]
mod tests {
    use crate::util::testio::read_test_file;
    use hex_literal::hex;
    use std::convert::{TryFrom, TryInto};

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
            SgxEndorsements::try_from(data.as_slice()).expect("failed to parse endorsements");

        assert_eq!(1, endorsements._version)
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

    #[test]
    fn parse_tcb_info_v3() {
        let data = read_test_file("tests/data/tcb_info_v3.json");
        let tcb_info: TcbInfo = serde_json::from_slice(&data).unwrap();
        assert_eq!(TcbInfoVersion::V3, tcb_info.version);
        assert_eq!(hex!("00606A000000"), tcb_info.fmspc);
        assert_eq!(
            TcbStatus::SWHardeningNeeded,
            tcb_info.tcb_levels[0].tcb_status
        );
        assert!(tcb_info.tcb_levels[0]
            .advisory_ids
            .contains(&"INTEL-SA-00657".to_owned()));
        assert_eq!(
            [7, 9, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            tcb_info.tcb_levels[0].tcb.components()
        );
    }

    #[test]
    fn parse_tcb_info_v2() {
        let data = read_test_file("tests/data/tcb_info_v2.json");
        let tcb_info: TcbInfo = serde_json::from_slice(&data).unwrap();
        assert_eq!(TcbInfoVersion::V2, tcb_info.version);
        assert_eq!(hex!("00606A000000"), tcb_info.fmspc);
        assert_eq!(
            TcbStatus::SWHardeningNeeded,
            tcb_info.tcb_levels[0].tcb_status
        );
        assert!(tcb_info.tcb_levels[0].advisory_ids.is_empty());
        assert_eq!(
            [7, 9, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            tcb_info.tcb_levels[0].tcb.components()
        );
    }
}

#[derive(Deserialize)]
struct TcbInfoAndSignature<'a> {
    #[serde(rename = "tcbInfo", borrow)]
    tcb_info_raw: &'a RawValue,
    #[serde(deserialize_with = "deserialize_ecdsa_signature")]
    signature: EcdsaSig,
}

impl<'a> EcdsaSigned for TcbInfoAndSignature<'a> {
    fn data(&self) -> &'a [u8] {
        self.tcb_info_raw.get().as_bytes()
    }

    fn signature(&self) -> &EcdsaSigRef {
        &self.signature
    }
}

impl TcbInfoAndSignature<'_> {
    fn into_tcb_info(self, public_key: &EcKeyRef<Public>) -> Result<TcbInfo> {
        self.verify_signature(public_key).context("tcb info")?;
        let tcb_info: TcbInfo = serde_json::from_str(self.tcb_info_raw.get())
            .map_err(|e| Error::from(e).context("tcb info"))?;

        if tcb_info
            .tcb_levels
            .iter()
            .any(|e| e.tcb.version() != tcb_info.version)
        {
            return Err(Error::new(format!(
                "mismatched tcb info versions, should all be {:?}",
                tcb_info.version,
            )));
        }

        // tcb_type determines how to compare tcb level
        // currently, only 0 is valid
        if tcb_info.tcb_type != 0 {
            return Err(Error::new(format!(
                "unsupported tcb type {}",
                tcb_info.tcb_type,
            )));
        }
        Ok(tcb_info)
    }
}

/// Version of the TcbInfo JSON structure
///
/// In the PCS V3 API the TcbInfo version is V2, in the PCS V4 API the TcbInfo
/// version is V3. The V3 API includes advisoryIDs and changes the format of
/// the TcbLevel
#[derive(Deserialize, Debug, Eq, PartialEq)]
#[serde(try_from = "u16")]
pub(crate) enum TcbInfoVersion {
    V2 = 2,
    V3 = 3,
}

impl TryFrom<u16> for TcbInfoVersion {
    type Error = &'static str;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            2 => Ok(TcbInfoVersion::V2),
            3 => Ok(TcbInfoVersion::V3),
            _ => Err("Unsupported TCB Info version"),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TcbInfo {
    version: TcbInfoVersion,
    _issue_date: chrono::DateTime<Utc>,
    pub next_update: chrono::DateTime<Utc>,
    #[serde(with = "hex")]
    pub fmspc: [u8; 6],
    #[serde(with = "hex")]
    pub pce_id: [u8; 2],
    tcb_type: u16,
    _tcb_evaluation_data_number: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

impl Expireable for TcbInfo {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        // don't care about issue_date
        // 1. There's no notion of "valid before" like in X509
        // 2. These dates might be *very* recent, and we don't
        //    want to fail requests because of clock skew
        timestamp <= self.next_update.into()
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TcbLevel {
    pub tcb: Tcb,
    _tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", default)]
    pub advisory_ids: Vec<String>,
}

#[cfg(test)]
impl TcbLevel {
    /// Test only TcbLevel constructor
    pub(crate) fn from_parts(
        version: TcbInfoVersion,
        tcbcompsvn: [u8; 16],
        pcesvn: u16,
        tcb_status: TcbStatus,
        advisory_ids: Vec<String>,
    ) -> TcbLevel {
        let tcb = match version {
            TcbInfoVersion::V2 => Tcb::V2(TcbV2 {
                sgxtcbcomp01svn: tcbcompsvn[0],
                sgxtcbcomp02svn: tcbcompsvn[1],
                sgxtcbcomp03svn: tcbcompsvn[2],
                sgxtcbcomp04svn: tcbcompsvn[3],
                sgxtcbcomp05svn: tcbcompsvn[4],
                sgxtcbcomp06svn: tcbcompsvn[5],
                sgxtcbcomp07svn: tcbcompsvn[6],
                sgxtcbcomp08svn: tcbcompsvn[7],
                sgxtcbcomp09svn: tcbcompsvn[8],
                sgxtcbcomp10svn: tcbcompsvn[9],
                sgxtcbcomp11svn: tcbcompsvn[10],
                sgxtcbcomp12svn: tcbcompsvn[11],
                sgxtcbcomp13svn: tcbcompsvn[12],
                sgxtcbcomp14svn: tcbcompsvn[13],
                sgxtcbcomp15svn: tcbcompsvn[14],
                sgxtcbcomp16svn: tcbcompsvn[15],
                pcesvn,
            }),
            TcbInfoVersion::V3 => Tcb::V3(TcbV3 {
                sgxtcbcomponents: tcbcompsvn.map(|x| TcbComponentV3 { svn: x }),
                pcesvn,
            }),
        };
        Self {
            tcb,
            _tcb_date: Utc::now(),
            tcb_status,
            advisory_ids,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Deserialize)]
pub(crate) enum TcbStatus {
    UpToDate,
    OutOfDate,
    ConfigurationNeeded,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDateConfigurationNeeded,
    Revoked,
}

/// Contains information identifying a TcbLevel.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum Tcb {
    V2(TcbV2),
    V3(TcbV3),
}

impl Tcb {
    fn version(&self) -> TcbInfoVersion {
        match self {
            Tcb::V2(_) => TcbInfoVersion::V2,
            Tcb::V3(_) => TcbInfoVersion::V3,
        }
    }
}

#[derive(Deserialize, Debug)]
pub(crate) struct TcbV3 {
    sgxtcbcomponents: [TcbComponentV3; 16],
    pcesvn: u16,
}

#[derive(Deserialize, Debug, Clone, Copy)]
pub(crate) struct TcbComponentV3 {
    svn: u8,
}

#[derive(Deserialize, Debug)]
pub(crate) struct TcbV2 {
    sgxtcbcomp01svn: u8,
    sgxtcbcomp02svn: u8,
    sgxtcbcomp03svn: u8,
    sgxtcbcomp04svn: u8,
    sgxtcbcomp05svn: u8,
    sgxtcbcomp06svn: u8,
    sgxtcbcomp07svn: u8,
    sgxtcbcomp08svn: u8,
    sgxtcbcomp09svn: u8,
    sgxtcbcomp10svn: u8,
    sgxtcbcomp11svn: u8,
    sgxtcbcomp12svn: u8,
    sgxtcbcomp13svn: u8,
    sgxtcbcomp14svn: u8,
    sgxtcbcomp15svn: u8,
    sgxtcbcomp16svn: u8,
    pcesvn: u16,
}

impl Tcb {
    pub fn pcesvn(&self) -> u16 {
        match self {
            Self::V2(v2) => v2.pcesvn,
            Self::V3(v3) => v3.pcesvn,
        }
    }

    pub fn components(&self) -> [u8; 16] {
        match self {
            Self::V2(v2) => [
                v2.sgxtcbcomp01svn,
                v2.sgxtcbcomp02svn,
                v2.sgxtcbcomp03svn,
                v2.sgxtcbcomp04svn,
                v2.sgxtcbcomp05svn,
                v2.sgxtcbcomp06svn,
                v2.sgxtcbcomp07svn,
                v2.sgxtcbcomp08svn,
                v2.sgxtcbcomp09svn,
                v2.sgxtcbcomp10svn,
                v2.sgxtcbcomp11svn,
                v2.sgxtcbcomp12svn,
                v2.sgxtcbcomp13svn,
                v2.sgxtcbcomp14svn,
                v2.sgxtcbcomp15svn,
                v2.sgxtcbcomp16svn,
            ],
            Self::V3(v3) => v3.sgxtcbcomponents.map(|comp| comp.svn),
        }
    }
}

#[derive(Deserialize)]
struct QuotingEnclaveIdentityAndSignature<'a> {
    #[serde(borrow, rename = "enclaveIdentity")]
    enclave_identity_raw: &'a RawValue,
    #[serde(deserialize_with = "deserialize_ecdsa_signature")]
    signature: EcdsaSig,
}

impl<'a> EcdsaSigned for QuotingEnclaveIdentityAndSignature<'a> {
    fn data(&self) -> &'a [u8] {
        self.enclave_identity_raw.get().as_bytes()
    }

    fn signature(&self) -> &EcdsaSigRef {
        &self.signature
    }
}

impl QuotingEnclaveIdentityAndSignature<'_> {
    fn into_enclave_identity(self, public_key: &EcKeyRef<Public>) -> Result<EnclaveIdentity> {
        self.verify_signature(public_key)?;
        let identity: EnclaveIdentity = serde_json::from_str(self.enclave_identity_raw.get())
            .map_err(|e| Error::from(e).context("enclave identity"))?;
        if identity.version != ENCLAVE_IDENTITY_V2 {
            return Err(Error::new(format!(
                "unsupported enclave identity version {}",
                identity.version
            )));
        }
        Ok(identity)
    }
}

/// The version of EnclaveIdentity JSON structure
const ENCLAVE_IDENTITY_V2: u16 = 2;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnclaveIdentity {
    pub id: EnclaveType,
    version: u16,
    _issue_date: chrono::DateTime<Utc>,
    pub next_update: chrono::DateTime<Utc>,
    _tcb_evaluation_data_number: u16,
    #[serde(with = "hex")]
    pub miscselect: UInt32LE,
    #[serde(with = "hex")]
    pub miscselect_mask: UInt32LE,
    #[serde(with = "hex")]
    pub attributes: [u8; 16],
    #[serde(with = "hex")]
    pub attributes_mask: [u8; 16],
    #[serde(with = "hex")]
    pub mrsigner: [u8; 32],
    pub isvprodid: u16,
    pub tcb_levels: Vec<QeTcbLevel>,
}

impl EnclaveIdentity {
    /// Find the latest tcb level in the Enclave Identity that the
    /// QE report is less than or equal to.
    ///
    /// This follows steps 4.a-c
    /// in <https://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity-v3>
    pub fn tcb_status(&self, report_isvsvn: u16) -> &QeTcbStatus {
        // tcb_levels is in descending order by ISVSVN according to spec
        self.tcb_levels
            .iter()
            .find(|tcb_level| tcb_level.tcb.isvsvn <= report_isvsvn)
            .map(|level| &level.tcb_status)
            .unwrap_or(&QeTcbStatus::Revoked)
    }
}

impl Expireable for EnclaveIdentity {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        // don't care about issue_date
        // 1. There's no notion of "valid before" like in X509
        // 2. These dates might be *very* recent, and we don't
        //    want to fail requests because of clock skew
        timestamp <= self.next_update.into()
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum EnclaveType {
    /// Quoting Enclave
    Qe,
    /// Quote Verification Enclave (which we won't use)
    Qve,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QeTcbLevel {
    // We don't bother deserializing the field "advisoryIds" since
    // we fetch the advisory ids from the matching TCB level
    tcb: QeTcb,
    _tcb_date: chrono::DateTime<Utc>,
    tcb_status: QeTcbStatus,
}

#[cfg(test)]
impl QeTcbLevel {
    pub(crate) fn from_parts(tcb_status: QeTcbStatus, isvsvn: u16) -> Self {
        Self {
            _tcb_date: Utc::now(),
            tcb_status,
            tcb: QeTcb { isvsvn },
        }
    }
}

#[derive(Deserialize, Debug)]
struct QeTcb {
    isvsvn: u16,
}

/// The TCB Status returned by "Get Quoting Enclave Identity"
///
/// Note that this is a subset of the [`TcbStatus`] associated with the
/// the [`TcbLevel`]. If the `QeTcbStatus` is not `UpToDate`, the QE
/// should generally be rejected, otherwise the corresponding
/// `TcbLevel` should be found and consulted.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum QeTcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
}
