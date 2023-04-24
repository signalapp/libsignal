//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! SGX quote, ported from Open Enclave headers in v0.17.7.
//!
//! See <https://download.01.org/intel-sgx/sgx-dcap/1.7/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf> section A.4

use boring::bn::BigNum;
use boring::ec::{EcGroup, EcKey};
use boring::ecdsa::{EcdsaSig, EcdsaSigRef};
use boring::error::ErrorStack;
use boring::nid::Nid;
use boring::pkey::Public;
use sha2::Digest;
use std::convert::{TryFrom, TryInto};
use std::intrinsics::transmute;
use std::time::SystemTime;

use crate::dcap::cert_chain::CertChain;
use crate::dcap::ecdsa::{ecdsa_signature_from_bytes, EcdsaSigned};
use crate::dcap::sgx_report_body::SgxReportBody;
use crate::dcap::sgx_x509::SgxPckExtension;
use crate::dcap::{Error, Expireable};
use crate::endian::*;
use crate::error::Context;
use crate::util;

pub(crate) struct SgxQuote<'a> {
    /// The Quote Header (A.4.3) and the Independent
    /// Software Vendor (ISV) enclave report
    pub quote_body: SgxQuoteBody,

    /// Contains signatures, the quoting enclave report, and other
    /// material for verifying `quote_body`. The "Quote Signature Data"
    /// in A.4.1
    pub support: SgxQuoteSupport<'a>,
}

impl<'a> SgxQuote<'a> {
    /// Read an SgxQuote from the `bytes`, advancing bytes
    /// by the number of bytes consumed
    pub fn read(bytes: &mut &'a [u8]) -> super::Result<Self> {
        if bytes.len() < std::mem::size_of::<SgxQuoteBody>() {
            return Err(Error::new("incorrect buffer size"));
        }

        // check the version before we try to deserialize (don't advance bytes)
        let version = u16::from_le_bytes(bytes[0..2].try_into().expect("correct size"));
        if version != QUOTE_V3 {
            return Err(Error::new("unsupported quote version"));
        }
        let quote_body = util::read_array::<{ std::mem::size_of::<SgxQuoteBody>() }>(bytes);
        let quote_body = SgxQuoteBody::try_from(quote_body)?;

        if bytes.len() < std::mem::size_of::<u32>() {
            return Err(Error::new("underflow reading signature length"));
        }
        let signature_len = util::read_u32_le(bytes);
        if bytes.len() < signature_len as usize {
            return Err(Error::new("underflow reading signature"));
        }
        let support = SgxQuoteSupport::read(bytes)?;

        Ok(SgxQuote {
            quote_body,
            support,
        })
    }
}

/// Reads the bytes backing `value`.
///
/// SAFETY: `T` must be a `repr(C)` or `repr(transparent)` struct with no interior padding
/// (alignment of 1), and all its fields recursively the same down to bytes (`u8` or `i8`) or
/// fixed-sized arrays of bytes.
///
/// Rust can only check the alignment of the top-level type; it can't check the repr or the
/// properties of fields. Be careful!
unsafe fn bytes_of<T>(value: &T) -> &[u8] {
    assert_eq!(1, std::mem::align_of::<T>());
    let len = std::mem::size_of::<T>();
    let ptr = value as *const T;
    std::slice::from_raw_parts(ptr as *const u8, len)
}

/// Verifies the signature of the quote header + ISV report, which must be signed
/// by the quoting enclave attest key
impl<'a> EcdsaSigned for SgxQuote<'a> {
    fn data(&self) -> &[u8] {
        unsafe { bytes_of(&self.quote_body) }
    }

    fn signature(&self) -> &EcdsaSigRef {
        &self.support.isv_signature
    }
}

/// The version of the SGX Quote (A.4.3)
const QUOTE_V3: u16 = 3;

// https://github.com/openenclave/openenclave/tree/v0.17.7
// sgx_quote.h
#[derive(Debug)]
#[repr(C)]
pub(crate) struct SgxQuoteBody {
    //    /* (0) */
    //    uint16_t version;
    version: UInt16LE,

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
    pub qe_vendor_id: [u8; 16],

    //    /* (28) */
    //    uint8_t user_data[20];
    user_data: [u8; 20],

    //    /* (48) */
    //    sgx_report_body_t report_body;
    pub report_body: SgxReportBody,
    //    /* (432) */
}

static_assertions::const_assert_eq!(1, std::mem::align_of::<SgxQuoteBody>());
static_assertions::const_assert_eq!(432, std::mem::size_of::<SgxQuoteBody>());

#[derive(Debug)]
enum SgxAttestationAlgorithm {
    _EPID = 0,
    _Reserved,
    EcdsaP256,
    _EcdsaP384,
}

impl TryFrom<[u8; std::mem::size_of::<SgxQuoteBody>()]> for SgxQuoteBody {
    type Error = super::Error;

    fn try_from(bytes: [u8; std::mem::size_of::<SgxQuoteBody>()]) -> super::Result<Self> {
        let quote_body: SgxQuoteBody = unsafe { transmute(bytes) };
        if quote_body.version.value() != QUOTE_V3 {
            return Err(Error::new(format!(
                "unsupported SGX quote version: {}",
                quote_body.version.value(),
            )));
        }
        // the type of the attestation signing key - we only speak ECDSA-256-with-P-256 curve
        if quote_body.sign_type.value() != SgxAttestationAlgorithm::EcdsaP256 as u16 {
            return Err(Error::new(format!(
                "unsupported SGX attestation algorithm: {}",
                quote_body.sign_type.value(),
            )));
        }

        Ok(quote_body)
    }
}

impl<'a> Expireable for SgxQuote<'a> {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        // quote_body is not expireable
        self.support.valid_at(timestamp)
    }
}

#[derive(Debug, PartialEq)]
enum CertificationKeyType {
    _PpidCleartext = 1,
    _PpidRsa2048Encrypted,
    _PpidRsa3072Encrypted,
    _PckCleartext,
    PckCertChain,
    _EcdsaSigAuxData,
}

/// In the intel docs, this is A4.4: "ECDSA 256-bit Quote Signature Data Structure"
///
/// This can be used to validate that the quoting enclave itself is valid, and then that
/// the quoting enclave has signed the ISV enclave report
pub(crate) struct SgxQuoteSupport<'a> {
    /// signature of the report header + report (SgxQuoteBody) by the attest key
    pub isv_signature: EcdsaSig,
    /// The public key used to generate isv_signature
    pub attest_pub_key: [u8; 64],
    /// report of the quoting enclave (QE)
    pub qe_report_body: SgxReportBody,
    /// signature of the quoting enclave report using the PCK cert key
    pub qe_report_signature: EcdsaSig,
    /// sha256(attest pub key + auth_data) should match QE report data
    pub auth_data: &'a [u8],
    /// the certificate chain for the pck signer
    pub pck_cert_chain: CertChain,
    /// custom SGX extension that should be present on the pck signer cert
    pub pck_extension: SgxPckExtension,
}

/// Validates the signature of the QE report, which must be
/// signed by the pck_cert leaf public key
impl<'a> EcdsaSigned for SgxQuoteSupport<'a> {
    fn data(&self) -> &[u8] {
        unsafe { bytes_of(&self.qe_report_body) }
    }

    fn signature(&self) -> &EcdsaSigRef {
        &self.qe_report_signature
    }
}

impl<'a> SgxQuoteSupport<'a> {
    pub fn read(src: &mut &'a [u8]) -> super::Result<Self> {
        if src.len() < std::mem::size_of::<SgxEcdsaSignatureHeader>() {
            return Err(Error::new("incorrect buffer size"));
        }

        let header_bytes =
            util::read_array::<{ std::mem::size_of::<SgxEcdsaSignatureHeader>() }>(src);
        let header = SgxEcdsaSignatureHeader::try_from(header_bytes).context("signature header")?;

        if src.len() < header.auth_data_size.value() as usize {
            return Err(Error::new("buffer underflow"));
        }
        let auth_data = util::read_bytes(src, header.auth_data_size.value() as usize);
        if src.len() < std::mem::size_of::<u16>() + std::mem::size_of::<u32>() {
            return Err(Error::new("buffer underflow"));
        }
        let cert_key_type = util::read_u16_le(src);
        if cert_key_type != CertificationKeyType::PckCertChain as u16 {
            return Err(Error::new("unsupported certification key type"));
        }

        let cert_data_size = util::read_u32_le(src) as usize;

        if src.len() < cert_data_size {
            return Err(Error::new("remaining data does not match expected size"));
        }

        let pck_cert_chain = util::read_bytes(src, cert_data_size);
        let pck_cert_chain = CertChain::from_pem_data(pck_cert_chain).context("CertChain")?;

        // deserialize the custom intel sgx extension on the pck certificate
        // find the extension on the pck_cert that has the sgx ext OID
        let pck_ext = pck_cert_chain
            .leaf()
            .extensions()
            .and_then(|extensions| {
                extensions
                    .iter()
                    .find(|ext| SgxPckExtension::is_pck_ext(ext.object()))
            })
            .ok_or_else(|| Error::new("PCK certificate is missing SGX extension"))?;
        let pck_extension =
            SgxPckExtension::from_der(pck_ext.data().as_slice()).context("SgxPckExtension")?;

        let signature = SgxQuoteSupport {
            isv_signature: ecdsa_signature_from_bytes(&header.signature)
                .context("isv_signature")?,
            attest_pub_key: header.attest_pub_key,
            qe_report_body: header.qe_report_body,
            qe_report_signature: ecdsa_signature_from_bytes(&header.qe_report_signature)
                .context("qe_report_signature")?,
            auth_data,
            pck_cert_chain,
            pck_extension,
        };

        Ok(signature)
    }

    /// Return the public part of the key generated by the quoting enclave
    ///
    /// The quote header and the ISV report must be signed by this key
    pub fn attest_key(&self) -> super::Result<EcKey<Public>> {
        fn key(x: &[u8], y: &[u8]) -> Result<EcKey<Public>, ErrorStack> {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let xbn = BigNum::from_slice(x)?;
            let ybn = BigNum::from_slice(y)?;

            EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn)
        }

        key(&self.attest_pub_key[..32], &self.attest_pub_key[32..])
            .map_err(|e| Error::from(e).context("attestation public key"))
    }

    /// Verify the report generated by the quoting enclave
    ///
    /// By specification, the quoting enclave report data `sgx_report_data_bytes`, must be
    /// SHA256(ECDSA Attestation Key || QE Authentication Data) || 32- 0x00’s
    pub fn verify_qe_report(&self) -> super::Result<()> {
        let mut h = sha2::Sha256::new();
        // Explicitly pass a slice to avoid generating another copy of update().
        h.update(&self.attest_pub_key[..]);
        h.update(self.auth_data);
        let digest = h.finalize();
        assert_eq!(digest.len(), 32);

        if *digest != self.qe_report_body.sgx_report_data_bytes[..digest.len()] {
            #[cfg(not(fuzzing))]
            return Err(Error::new(
                "Quoting enclave report should be hash of attestation key and auth data",
            ));
        }
        if self.qe_report_body.sgx_report_data_bytes[digest.len()..] != [0; 32] {
            return Err(Error::new("Quoting enclave report should be zero padded"));
        }

        Ok(())
    }
}

impl<'a> Expireable for SgxQuoteSupport<'a> {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.pck_cert_chain.valid_at(timestamp)
    }
}

#[derive(Debug)]
#[repr(C)]
struct SgxEcdsaSignatureHeader {
    signature: [u8; 64],
    attest_pub_key: [u8; 64],
    qe_report_body: SgxReportBody,
    qe_report_signature: [u8; 64],
    auth_data_size: UInt16LE,
}

static_assertions::const_assert_eq!(1, std::mem::align_of::<SgxEcdsaSignatureHeader>());
static_assertions::const_assert_eq!(578, std::mem::size_of::<SgxEcdsaSignatureHeader>());

impl TryFrom<[u8; std::mem::size_of::<SgxEcdsaSignatureHeader>()]> for SgxEcdsaSignatureHeader {
    type Error = super::Error;

    fn try_from(
        bytes: [u8; std::mem::size_of::<SgxEcdsaSignatureHeader>()],
    ) -> super::Result<Self> {
        Ok(unsafe { transmute(bytes) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use boring::pkey::Private;
    use std::convert::TryFrom;
    use std::fs;
    use std::path::Path;

    use crate::dcap::cert_chain::testutil::cert_chain;

    #[test]
    fn valid_quote_from_disk() {
        let quote = quote_bytes();
        let quote = SgxQuote::read(&mut quote.as_slice()).unwrap();
        quote
            .support
            .verify_signature(&quote.support.pck_cert_chain.leaf_pub_key().unwrap())
            .expect("QE report should be signed by pck cert");

        quote
            .support
            .verify_qe_report()
            .expect("QE report should be valid");

        quote
            .verify_signature(&quote.support.attest_key().unwrap())
            .expect("ISV report should be signed with attest key");
    }

    fn generate_key() -> EcKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        EcKey::from_private_components(&group, key.private_key(), key.public_key()).unwrap()
    }

    #[derive(PartialEq, Debug)]
    enum FailInfo {
        Success,
        Qe,
        Isv,
    }

    fn verify<F>(f: F) -> FailInfo
    where
        F: FnOnce(&mut SgxQuote),
    {
        let quote = quote_bytes();
        let mut quote = SgxQuote::read(&mut quote.as_slice()).unwrap();
        f(&mut quote);
        if quote
            .support
            .verify_signature(&quote.support.pck_cert_chain.leaf_pub_key().unwrap())
            .is_err()
        {
            FailInfo::Qe
        } else if quote
            .verify_signature(&quote.support.attest_key().unwrap())
            .is_err()
        {
            FailInfo::Isv
        } else {
            FailInfo::Success
        }
    }

    #[test]
    fn isv_sig_bad_body() {
        assert_eq!(
            verify(|quote| quote.quote_body.reserved[0] += 1),
            FailInfo::Isv
        )
    }

    #[test]
    fn isv_sig_bad_mrenclave() {
        assert_eq!(
            verify(|quote| quote.quote_body.report_body.mrenclave[0] += 1),
            FailInfo::Isv
        )
    }

    #[test]
    fn isv_sig_bad_sig() {
        let key = generate_key();
        assert_eq!(
            verify(|quote| {
                quote.support.isv_signature = EcdsaSig::sign("test".as_bytes(), &key).unwrap()
            }),
            FailInfo::Isv
        )
    }

    #[test]
    fn qe_sig_bad_report() {
        assert_eq!(
            verify(|quote| quote.support.qe_report_body.sgx_report_data_bytes[0] += 1),
            FailInfo::Qe
        )
    }

    #[test]
    fn qe_sig_bad_sig() {
        let key = generate_key();
        let sig = EcdsaSig::sign("test".as_bytes(), &key).unwrap();
        assert_eq!(
            verify(|quote| quote.support.qe_report_signature = sig),
            FailInfo::Qe
        )
    }

    #[test]
    fn qe_sig_bad_signer() {
        assert_eq!(
            verify(|quote| quote.support.pck_cert_chain = cert_chain(2)),
            FailInfo::Qe
        )
    }

    #[test]
    fn qe_report_bad_attest_key() {
        let support = quote_support_bytes();
        let mut support = SgxQuoteSupport::read(&mut support.as_slice()).unwrap();
        support.attest_pub_key[0] += 1;
        assert!(support.verify_qe_report().is_err());
    }

    #[test]
    fn qe_report_bad_report() {
        let support = quote_support_bytes();
        let mut support = SgxQuoteSupport::read(&mut support.as_slice()).unwrap();
        support.qe_report_body.sgx_report_data_bytes[0] += 1;
        assert!(support.verify_qe_report().is_err());
    }

    #[test]
    fn qe_report_bad_auth_data() {
        let mut support_bytes = quote_support_bytes();
        // corrupt the auth data, which follows SgxEcdsaSignatureHeader
        support_bytes[std::mem::size_of::<SgxEcdsaSignatureHeader>()] += 1;
        let support = SgxQuoteSupport::read(&mut support_bytes.as_slice()).unwrap();

        // signature should still work
        support
            .verify_signature(&support.pck_cert_chain.leaf_pub_key().unwrap())
            .unwrap();

        // but the report should be invalid
        assert!(support.verify_qe_report().is_err());
    }

    #[test]
    fn deserialize_bad_version() {
        let mut quote = quote_bytes();
        // 2 byte little endian version (version 3, set to version 4)
        assert_eq!(quote[0], 3);
        assert_eq!(quote[1], 0);
        quote[0] += 1;
        assert!(SgxQuote::read(&mut quote.as_slice()).is_err());
    }

    #[test]
    fn deserialize_underflow() {
        let quote = quote_bytes();
        // truncate support
        let mut quote = &quote[..std::mem::size_of::<SgxQuoteBody>()];
        assert!(SgxQuote::read(&mut quote).is_err());
    }

    #[test]
    fn deserialize_unsupported_key_type() {
        let mut support = quote_support_bytes();
        let auth_data_size = {
            let mut header_bytes = [0u8; std::mem::size_of::<SgxEcdsaSignatureHeader>()];
            header_bytes
                .copy_from_slice(&support[..std::mem::size_of::<SgxEcdsaSignatureHeader>()]);
            let header = SgxEcdsaSignatureHeader::try_from(header_bytes).unwrap();
            header.auth_data_size.value() as usize
        };

        // corrupt key type
        // support is {SgxEcdsaSignatureHeader, auth_data_size (2), auth_data, key type...}
        support[std::mem::size_of::<SgxEcdsaSignatureHeader>() + auth_data_size] += 1;

        assert!(SgxQuote::read(&mut support.as_slice()).is_err());
    }

    fn quote_bytes() -> Vec<u8> {
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/dcap.evidence"))
            .expect("failed to read file")
    }

    fn quote_support_bytes() -> Vec<u8> {
        let bytes =
            fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/dcap.evidence"))
                .expect("failed to read file");
        // bytes are {SgxQuoteBody, SupportLength (4), Support}
        let mut slice = &bytes[std::mem::size_of::<SgxQuoteBody>()..];
        let signature_len = util::read_u32_le(&mut slice);
        slice[..signature_len as usize].to_vec()
    }
}
