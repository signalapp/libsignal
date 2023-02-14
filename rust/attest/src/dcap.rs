//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Implements SGX DCAP attestation verification.
// https://www.intel.com/content/dam/develop/external/us/en/documents/intel-sgx-support-for-third-party-attestation-801017.pdf
// https://api.portal.trustedservices.intel.com/provisioning-certification

// 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK certificate.
// 2. Verify no keys in the chain have been revoked.
// 3. Verify the Quoting Enclave is from a suitable source and is up to date.
// 4. Verify the status of the Intel® SGX TCB described in the chain.
// 5. Verify the enclave measurements in the Quote reflect an enclave identity expected.

// Azure DCAP Client dcap_provider.cpp
// sgx_ql_get_quote_config() -> sgx_ql_config_t
// and pretty much all sgx_ql_get_*

// The first value, the Provisioning Certification
// Key, is an IETF RFC 6090 [5] compliant 256 bit Elliptic
// Curve signing key, using the NIST p-256 curve.

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

use boring::asn1::{Asn1Time, Asn1TimeRef};
use boring::bn::BigNumContext;
use boring::ec::*;
use boring::error::ErrorStack;
use boring::nid::Nid;
use boring::pkey::{PKey, PKeyRef, Public};
use boring::x509::crl::X509CRLRef;
use boring::x509::store::{X509Store, X509StoreBuilder};
use boring::x509::verify::X509VerifyFlags;
use boring::x509::{X509Ref, X509VerifyResult, X509};
use hex::ToHex;
use lazy_static::lazy_static;
use uuid::Uuid;

use crate::dcap::ecdsa::EcdsaSigned;
use crate::dcap::endorsements::{
    EnclaveType, QeTcbStatus, SgxEndorsements, TcbInfo, TcbLevel, TcbStatus,
};
use crate::dcap::evidence::Evidence;
pub use crate::dcap::sgx_report_body::MREnclave;
use crate::dcap::sgx_report_body::SgxFlags;
use crate::dcap::sgx_x509::SgxPckExtension;
use crate::error::{Context, ContextError};

pub(crate) mod cert_chain;
mod ecdsa;
mod endorsements;
mod evidence;
mod revocation_list;
mod sgx_quote;
mod sgx_report_body;
mod sgx_x509;

#[cfg(test)]
mod fakes;

#[derive(Debug)]
pub struct AttestationError {
    message: String,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for AttestationError {}

impl From<Error> for AttestationError {
    fn from(e: Error) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

pub(crate) struct DcapErrorDomain;
pub(crate) type Error = ContextError<DcapErrorDomain>;

type Result<T> = std::result::Result<T, Error>;

pub(crate) trait Expireable {
    fn valid_at(&self, timestamp: SystemTime) -> bool;
}

/// Intel public key that signs all root certificates for DCAP
const INTEL_ROOT_PUB_KEY: &[u8] = &[
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
    0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25,
    0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
    0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73,
    0x94,
];

/// Returns a `Result` containing a map of claims extracted from the evidence when successful,
/// or an attestation verification error when not
///
/// * `expected_mrenclave` - The MRENCLAVE that the quote must match
/// * `acceptable_sw_advisories` - In the event that the remote TCB has known vulnerabilities that
///                                require SW mitigations, the list of vulnerabilities that are
///                                known to be mitigated in `expected_mrenclave`.
/// * `current_time` - The current system time
pub fn verify_remote_attestation(
    evidence_bytes: &[u8],
    endorsement_bytes: &[u8],
    expected_mrenclave: &MREnclave,
    acceptable_sw_advisories: &[&str],
    current_time: SystemTime,
) -> std::result::Result<HashMap<String, Vec<u8>>, AttestationError> {
    let attestation = attest(evidence_bytes, endorsement_bytes, current_time)?;

    // 4. Verify the status of the Intel® SGX TCB described in the chain.
    if let TcbStanding::SWHardeningNeeded { advisory_ids } = attestation.tcb_standing {
        if advisory_ids
            .iter()
            .any(|id| !acceptable_sw_advisories.contains(&id.as_str()))
        {
            return Err(Error::new(format!(
                "TCB contains unmitigated unaccepted advisory ids: {:?}",
                advisory_ids
            ))
            .into());
        }
    }

    // 5. Verify the enclave measurements in the Quote reflect an enclave identity expected.
    if expected_mrenclave != &attestation.mrenclave {
        return Err(Error::new(format!(
            "expected mrenclave {}, was {}",
            expected_mrenclave.encode_hex::<String>(),
            attestation.mrenclave.encode_hex::<String>(),
        ))
        .into());
    }

    Ok(attestation.claims)
}

/// Parses evidence/endorsements and builds a map of metrics
pub fn attestation_metrics(
    evidence_bytes: &[u8],
    endorsement_bytes: &[u8],
) -> std::result::Result<HashMap<String, i64>, AttestationError> {
    let evidence = evidence::Evidence::try_from(evidence_bytes).context("evidence")?;
    let endorsements =
        endorsements::SgxEndorsements::try_from(endorsement_bytes).context("endorsements")?;

    fn asn2unix(ts: &Asn1TimeRef) -> std::result::Result<i64, AttestationError> {
        let diff = Asn1Time::from_unix(0)
            .expect("0 is valid unix time")
            .diff(ts)
            .map_err(|e| Error::from(e).context("converting attestation timestamps"))?;

        const DAY_SECS: i64 = 24 * 60 * 60;
        let secs: i64 = diff.days as i64 * DAY_SECS + diff.secs as i64;
        Ok(secs)
    }
    let pck_crl = endorsements.pck_issuer_crl.crl();
    let root_crl = endorsements.root_crl.crl();

    let ret = [
        (
            "pck_not_before_ts",
            asn2unix(evidence.quote.support.pck_cert_chain.leaf().not_before())?,
        ),
        (
            "pck_not_after_ts",
            asn2unix(evidence.quote.support.pck_cert_chain.leaf().not_after())?,
        ),
        (
            "tcb_signer_not_before_ts",
            asn2unix(endorsements.tcb_issuer_chain.leaf().not_before())?,
        ),
        (
            "tcb_signer_not_after_ts",
            asn2unix(endorsements.tcb_issuer_chain.leaf().not_after())?,
        ),
        (
            "root_not_before_ts",
            asn2unix(endorsements.tcb_issuer_chain.root().not_before())?,
        ),
        (
            "root_not_after_ts",
            asn2unix(endorsements.tcb_issuer_chain.root().not_after())?,
        ),
        (
            "pck_crl_last_update_ts",
            pck_crl.last_update().map_or(Ok(0), asn2unix)?,
        ),
        (
            "pck_crl_next_update_ts",
            pck_crl.next_update().map_or(Ok(0), asn2unix)?,
        ),
        (
            "root_crl_last_update_ts",
            root_crl.last_update().map_or(Ok(0), asn2unix)?,
        ),
        (
            "root_crl_next_update_ts",
            root_crl.next_update().map_or(Ok(0), asn2unix)?,
        ),
        (
            "tcb_info_expiration_ts",
            endorsements.tcb_info.next_update.timestamp(),
        ),
        (
            "qe_identity_expiration_ts",
            endorsements.qe_id_info.next_update.timestamp(),
        ),
    ];
    Ok(ret.iter().map(|(k, v)| (k.to_string(), *v)).collect())
}

/// Enclave information returned by an intel-trusted
/// enclave. The receiver must check that the enclave:
/// - is running the expected binary (via `mrenclave`)
/// - has a recent enough attestation (via `last_attest_time`)
/// - has an up to date tcb OR has acceptable SW advisories
#[derive(Debug)]
pub(crate) struct Attestation {
    tcb_standing: TcbStanding,
    mrenclave: MREnclave,
    claims: HashMap<String, Vec<u8>>,
}

/// Validate that the returned report/claims are generated
/// from a trusted intel SGX enclave
///
/// Users must then check if the returned trusted report indicates
/// that the remote device has the correct SW version and is from
/// an up to date platform
fn attest(
    evidence_bytes: &[u8],
    endorsement_bytes: &[u8],
    current_time: SystemTime,
) -> Result<Attestation> {
    let evidence = evidence::Evidence::try_from(evidence_bytes).context("evidence")?;
    let endorsements =
        endorsements::SgxEndorsements::try_from(endorsement_bytes).context("endorsements")?;
    attest_impl(evidence, endorsements, &INTEL_PKEY, current_time)
}

fn attest_impl(
    evidence: Evidence,
    endorsements: SgxEndorsements,
    trusted_root_pkey: &PKeyRef<Public>,
    current_time: SystemTime,
) -> Result<Attestation> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK certificate.
    // 2. Verify no keys in the chain have been revoked.
    // verify the time parameter falls within “not before” and “not after” metadata
    verify_expiration(current_time, &evidence).context("evidence")?;
    verify_expiration(current_time, &endorsements).context("endorsements")?;
    verify_certificates(trusted_root_pkey, &evidence, &endorsements, current_time)?;

    // 3. Verify the Quoting Enclave is from a suitable source and is up to date
    // verify the quoting enclave identity
    verify_enclave_source(&evidence, &endorsements)?;
    verify_enclave_signatures(&evidence)?;

    // find the TCB standing of the enclave
    let tcb_standing = verify_tcb_status(&evidence, &endorsements)?;

    // everything in the quote is verified. lastly, check the custom claims hash matches
    // the report data, and then return the claims map
    verify_claims_hash(&evidence)?;

    // clients should only trust MRENCLAVE values from a non-debug
    // build. But, as an extra precaution, verify that the remote
    // enclave is not running in debug mode
    let report = &evidence.quote.quote_body.report_body;
    if report.has_flag(SgxFlags::DEBUG) {
        return Err(Error::new("Application enclave in debug mode"));
    }

    Ok(Attestation {
        tcb_standing,
        mrenclave: evidence.quote.quote_body.report_body.mrenclave,
        claims: evidence.claims.map,
    })
}

const INTEL_QE_VENDOR_ID: Uuid = uuid::uuid!("939a7233-f79c-4ca9-940a-0db3957f0607");
lazy_static! {
    static ref INTEL_PKEY: PKey<Public> = {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("allocate curve");
        let mut ctx = BigNumContext::new().expect("allocate bignum");
        let point = EcPoint::from_bytes(&group, INTEL_ROOT_PUB_KEY, &mut ctx)
            .expect("static intel key should parse");
        let trusted_root_pubkey = EcKey::from_public_key(&group, &point).expect("should convert");
        PKey::from_ec_key(trusted_root_pubkey).expect("ec key should convert")
    };
}

/// Verify that the various certificate chains and CRLs are rooted
/// in `trusted_pkey`
fn verify_certificates(
    trusted_pkey: &PKeyRef<Public>,
    evidence: &Evidence,
    endorsements: &SgxEndorsements,
    current_time: SystemTime,
) -> Result<()> {
    let root_ca: &X509 = endorsements.tcb_issuer_chain.root();
    let root_crl = endorsements.root_crl.crl();

    let trusted = root_trust_store(root_ca, root_crl, trusted_pkey, current_time)
        .context("root trust store")?;

    // note: Since we already must trust the intel root key,
    // this does not check for specific chain lengths or for
    // specific subjects on the certificate chains (contrast
    // with the intel code). This only checks that they are
    // valid chains in the RFC 5280 section 6 sense

    // validate the PCK crl against the root trust store, add it as trusted if it all checks out
    endorsements
        .pck_issuer_crl_chain
        .validate_chain(&trusted, &[endorsements.pck_issuer_crl.crl()])
        .context("pck crl")?;
    let trusted = from_trusted(
        &[root_ca],
        &[root_crl, endorsements.pck_issuer_crl.crl()],
        current_time,
    )
    .context("trust store with PCK crl")?;

    // validate all remaining certificates (steps 1 and 2)
    endorsements
        .tcb_issuer_chain
        .validate_chain(&trusted, &[])
        .context("tcb issuer")?;
    evidence
        .quote
        .support
        .pck_cert_chain
        .validate_chain(&trusted, &[])
        .context("pck")?;
    endorsements
        .qe_id_issuer_chain
        .validate_chain(&trusted, &[])
        .context("qe id issuer")?;
    Ok(())
}

/// Create a trust store including the root certificate and crl, if they have been signed by the
/// root public key
fn root_trust_store(
    root_ca: &X509Ref,
    root_crl: &X509CRLRef,
    root_key: &PKeyRef<Public>,
    current_time: SystemTime,
) -> Result<X509Store> {
    // should be self issued
    if X509VerifyResult::OK != root_ca.issued(root_ca) {
        return Err(Error::new("Invalid root certificate (not self signed)"));
    }

    // should be signed with known root key
    if !root_ca.verify(root_key).unwrap_or(false) {
        #[cfg(not(fuzzing))]
        return Err(Error::new(
            "Invalid root certificate (not signed by root pub key)",
        ));
    }

    if !root_crl.verify(root_key).unwrap_or(false) {
        #[cfg(not(fuzzing))]
        return Err(Error::new("Root CRL failed verification"));
    }
    from_trusted(&[root_ca], &[root_crl], current_time)
}

/// Create a trust store from previously validated certificates and crls
pub(crate) fn from_trusted(
    trusted_certs: &[&X509Ref],
    trusted_crls: &[&X509CRLRef],
    current_time: SystemTime,
) -> Result<X509Store> {
    let build = || -> std::result::Result<X509Store, ErrorStack> {
        let mut store_builder = X509StoreBuilder::new().expect("can make a fresh X509StoreBuilder");
        store_builder
            .param_mut()
            .set_flags(
                X509VerifyFlags::CRL_CHECK
                    | X509VerifyFlags::CRL_CHECK_ALL
                    | X509VerifyFlags::X509_STRICT,
            )
            .expect("supports CRL checking flags");
        store_builder.param_mut().set_time(
            current_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("current time is after 1970")
                .as_secs()
                .try_into()
                .expect("haven't yet overflowed time_t"),
        );
        for &cert in trusted_certs {
            store_builder.add_cert(cert.to_owned())?;
        }
        for &crl in trusted_crls {
            store_builder.add_crl(crl.to_owned())?;
        }
        Ok(store_builder.build())
    };
    build().map_err(|e| Error::from(e).context("building trusted certificate store"))
}

fn verify_expiration(timestamp: SystemTime, expireable: &dyn Expireable) -> Result<()> {
    if !expireable.valid_at(timestamp) {
        let epoch_duration = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::new("invalid timestamp provided for expiration check"))?;
        return Err(Error::new(format!(
            "attestation is not valid for {}",
            epoch_duration.as_secs(),
        )));
    }

    Ok(())
}

/// Verify the reported enclave matches a valid, up-to-date quoting enclave issued by intel
///
/// This follows the steps outlined in:
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity-v3>
fn verify_enclave_source(evidence: &Evidence, endorsements: &SgxEndorsements) -> Result<()> {
    // verify the qe vendor is intel
    Uuid::from_slice(&evidence.quote.quote_body.qe_vendor_id)
        .ok()
        .filter(|uuid| uuid == &INTEL_QE_VENDOR_ID)
        .ok_or_else(|| {
            Error::new(format!(
                "QE Vendor ID: {} not Intel",
                evidence
                    .quote
                    .quote_body
                    .qe_vendor_id
                    .encode_hex::<String>()
            ))
        })?;

    // compare mrsigner from QE identity and quote’s QE report
    let qe_identity = &endorsements.qe_id_info;
    if qe_identity.mrsigner != evidence.quote.support.qe_report_body.mrsigner {
        return Err(Error::new(format!(
            "qe mrsigner mismatch: expected {}, actual {}",
            hex::encode(qe_identity.mrsigner),
            hex::encode(evidence.quote.support.qe_report_body.mrsigner)
        )));
    }

    // compare isvprodid in report vs collateral
    let report_isvprodid = evidence.quote.support.qe_report_body.isvprodid.value();
    let collateral_isvprodid = qe_identity.isvprodid;
    if report_isvprodid != collateral_isvprodid {
        return Err(Error::new(format!(
            "qe isvprodid mismatch: expected {}, actual {}",
            report_isvprodid, collateral_isvprodid
        )));
    }

    // compare miscselect from QE identity and masked miscselect from quote’s QE report
    let qe_report_miscselect = evidence.quote.support.qe_report_body.miscselect.value();
    if qe_report_miscselect & qe_identity.miscselect_mask.value() != qe_identity.miscselect.value()
    {
        return Err(Error::new("qe miscselect mismatch"));
    }

    // compare attributes from QE identity and masked attributes from quote’s QE report
    let qe_report_attributes = evidence.quote.support.qe_report_body.sgx_attributes;

    let calculated_mask = qe_identity
        .attributes_mask
        .iter()
        .zip(qe_report_attributes.iter())
        .map(|(a, b)| *a & *b);

    if calculated_mask
        .zip(qe_identity.attributes)
        .any(|(masked_attr, identity_attr)| masked_attr != identity_attr)
    {
        return Err(Error::new("attributes mismatch"));
    }

    if qe_identity.id != EnclaveType::Qe {
        return Err(Error::new(format!(
            "Invalid enclave identity for quoting enclave : {:?}",
            qe_identity.id
        )));
    }

    // Later, we will also lookup the tcb status in the TcbInfo but if
    // the Enclave Identity tcb status isn't up to date, we can fail right
    // away
    let report_isvsvn = evidence.quote.support.qe_report_body.isvsvn.value();
    let tcb_status = qe_identity.tcb_status(report_isvsvn);
    if tcb_status != &QeTcbStatus::UpToDate {
        return Err(Error::new(format!(
            "Enclave version tcb not up to date (was {:?})",
            tcb_status
        )));
    }

    Ok(())
}

/// Verify that the quoting enclave report is signed, contains
/// the expected contents, and that the ISV report is signed by
/// the quoting enclave
fn verify_enclave_signatures(evidence: &Evidence) -> Result<()> {
    // the quoting enclave (QE) report should be signed by the pck certificate
    let pck_pkey = evidence
        .quote
        .support
        .pck_cert_chain
        .leaf_pub_key()
        .context("pck cert chain")?;
    evidence
        .quote
        .support
        .verify_signature(&pck_pkey)
        .context("QE report")?;

    // the QE report should be the SHA256 of the attest key and auth data
    evidence
        .quote
        .support
        .verify_qe_report()
        .context("QE report")?;

    // and finally, the isv report should be signed by the attest key in the quote
    let attest_key = &*evidence
        .quote
        .support
        .attest_key()
        .context("quote attest key")?;
    evidence
        .quote
        .verify_signature(attest_key)
        .context("ISV report")?;

    Ok(())
}

/// Get the tcb status of the quoting enclave
///
/// Looks at the pck extension to determine the TCB level in the [`TcbInfo`]
/// If the TCB level is found, returns the status of that TCB level
///
/// This follows the steps outlined in:
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v3>
fn verify_tcb_status(evidence: &Evidence, endorsements: &SgxEndorsements) -> Result<TcbStanding> {
    // the tcb should be signed by the tcb issuer chain
    let tcb_info = &endorsements.tcb_info;
    let pck_ext = &evidence.quote.support.pck_extension;

    // make sure the tcb_info matches our enclave's model/PCE version
    if pck_ext.fmspc != tcb_info.fmspc {
        return Err(Error::new(format!(
            "tcb fmspc mismatch (pck extension fmspc was {:?}, tcb_info fmspc was {:?})",
            &pck_ext.fmspc, &tcb_info.fmspc
        )));
    }
    if pck_ext.pceid != tcb_info.pce_id {
        return Err(Error::new(format!(
            "tcb pceid mismatch (pck extension pceid was {:?}, tcb_info pceid was {:?})",
            &pck_ext.pceid, &tcb_info.pce_id
        )));
    }

    // Find the tcb status corresponding to our enclave in the tcb info
    // the consumer of dcap needs to decide which statuses are acceptable (either by
    // returning this up, or configuring acceptable statuses)
    TcbStanding::lookup(pck_ext, tcb_info)
}

/// Verify that the hash of the custom claims matches
/// the value in the ISV enclave report
fn verify_claims_hash(evidence: &Evidence) -> Result<()> {
    let claims_sha256 = evidence.claims.data_sha256();

    let (report_sha256, empty_bytes) = evidence
        .quote
        .quote_body
        .report_body
        .sgx_report_data_bytes
        .split_at(32);

    if empty_bytes != [0u8; 32] {
        return Err(Error::new("report data hash had unexpected data"));
    }

    if claims_sha256 != report_sha256 {
        #[cfg(not(fuzzing))]
        return Err(Error::new("custom claims hash mismatch"));
    }

    // OpenEnclave exposes the ability for hosts to request a valid report that
    // contains all zeros in the report_data via an ECALL, and if someone manages
    // to find claims that hash to all zeros, we still want to reject them.
    if report_sha256 == [0u8; 32] {
        return Err(Error::new("valid claims sha256 is all zeros, rejecting"));
    }

    Ok(())
}

#[derive(Debug)]
enum TcbStanding {
    /// The platform is trusted
    UpToDate,

    /// The platform is on a TCB level that is trustable if it is running software with appropriate
    /// software mitigations. The user should use another mechanism (e.g. MRENCLAVE) to verify that
    /// the returned advisory ids have been mitigated.
    SWHardeningNeeded { advisory_ids: Vec<String> },
}

impl TcbStanding {
    /// Determine the status of the tcb level for the platform represented by `pck_extension`
    ///
    /// Returns an error if the status is definitely not trustable (e.g., [`TcbStatus::Revoked`])
    /// but may return success if the status should be interpreted by the
    /// user (e.g., [`TcbStatus::SWHardeningNeeded`])
    ///
    /// This follows the steps 3.a-b outlined
    /// in <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v3>
    fn lookup(pck_extension: &SgxPckExtension, tcb_info: &TcbInfo) -> Result<TcbStanding> {
        // Go over the tcb_levels in the provided order and stop on the first tcb level
        // where the pck compsvn/pcesvn is >= tcb compsvn/pcesvn.
        // We assume these are sorted in the correct order based on the tcb info
        // api docs, though intel's dcap implementation re-sorts
        let first_matching_level = tcb_info
            .tcb_levels
            .iter()
            .find(|level| Self::in_tcb_level(level, pck_extension));

        first_matching_level
            .map(|level| match level.tcb_status {
                TcbStatus::UpToDate => Ok(TcbStanding::UpToDate),
                TcbStatus::SWHardeningNeeded => Ok(TcbStanding::SWHardeningNeeded {
                    advisory_ids: level.advisory_ids.clone(),
                }),
                _ => Err(Error::new(format!(
                    "invalid tcb status: {:?}",
                    level.tcb_status
                ))),
            })
            .unwrap_or_else(|| Err(Error::new("Unsupported TCB in pck extension")))
    }

    /// Returns true if all the pck components are >= all the tcb level components AND
    /// the pck pcesvn is >= tcb pcesvn
    fn in_tcb_level(level: &TcbLevel, pck_extension: &SgxPckExtension) -> bool {
        const SVN_LENGTH: usize = 16;
        let pck_components: &[u8; SVN_LENGTH] = &pck_extension.tcb.compsvn;

        pck_components
            .iter()
            .zip(level.tcb.components())
            .all(|(&p, l)| p >= l)
            && pck_extension.tcb.pcesvn >= level.tcb.pcesvn()
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;
    use std::time::{Duration, SystemTime};

    use crate::dcap::endorsements::{QeTcbLevel, TcbInfoVersion};
    use crate::dcap::fakes::FakeAttestation;
    use crate::util::testio::read_test_file;
    use boring::bn::BigNum;
    use hex_literal::hex;

    use super::*;

    const EXPECTED_MRENCLAVE: MREnclave =
        hex!("337ac97ce088a132daeb1308ea3159f807de4a827e875b2c90ce21bf4751196f");

    const ACCEPTED_SW_ADVISORIES: &[&str] = &["INTEL-SA-00615", "INTEL-SA-00657"];

    #[test]
    fn test_verify_remote_attestation() {
        let current_time: SystemTime =
            SystemTime::UNIX_EPOCH + Duration::from_millis(1674105089000);

        let evidence_bytes = read_test_file("tests/data/dcap.evidence");
        let endorsements_bytes = read_test_file("tests/data/dcap.endorsements");

        let pubkey = verify_remote_attestation(
            evidence_bytes.as_ref(),
            endorsements_bytes.as_ref(),
            &EXPECTED_MRENCLAVE,
            ACCEPTED_SW_ADVISORIES,
            current_time,
        )
        .unwrap()
        .get("pk")
        .unwrap()
        .to_owned();

        let expected_pubkey = hex::decode(read_test_file("tests/data/dcap.pubkey")).unwrap();
        assert_eq!(&expected_pubkey, pubkey.as_slice());
    }

    #[test]
    fn test_verify_remote_attestation_v3() {
        // Verify with collateral from the V3 PCS API (current version is V4)

        let current_time: SystemTime =
            SystemTime::UNIX_EPOCH + Duration::from_millis(1657856984000);

        let evidence_bytes = read_test_file("tests/data/dcap_v3.evidence");
        let endorsements_bytes = read_test_file("tests/data/dcap_v3.endorsements");

        let pubkey = verify_remote_attestation(
            evidence_bytes.as_ref(),
            endorsements_bytes.as_ref(),
            &hex!("e5eaa62da3514e8b37ccabddb87e52e7f319ccf5120a13f9e1b42b87ec9dd3dd"),
            &[],
            current_time,
        )
        .unwrap()
        .get("pk")
        .unwrap()
        .to_owned();

        let expected_pubkey = hex::decode(read_test_file("tests/data/dcap_v3.pubkey")).unwrap();
        assert_eq!(&expected_pubkey, pubkey.as_slice());
    }

    #[test]
    fn test_verify_remote_attestation_accepted_sw_advisories_not_present() {
        let current_time: SystemTime =
            SystemTime::UNIX_EPOCH + Duration::from_millis(1674105089000);

        let evidence_bytes = read_test_file("tests/data/dcap.evidence");
        let endorsements_bytes = read_test_file("tests/data/dcap.endorsements");

        let sw_advisories = &[ACCEPTED_SW_ADVISORIES, &["INTEL-SA-1234"]].concat();

        let pubkey = verify_remote_attestation(
            evidence_bytes.as_ref(),
            endorsements_bytes.as_ref(),
            &EXPECTED_MRENCLAVE,
            sw_advisories,
            current_time,
        )
        .unwrap()
        .get("pk")
        .unwrap()
        .to_owned();

        let expected_pubkey = hex::decode(read_test_file("tests/data/dcap.pubkey")).unwrap();
        assert_eq!(expected_pubkey, pubkey.as_slice());
    }

    #[test]
    fn test_attestation_metrics() {
        let evidence_bytes = read_test_file("tests/data/dcap.evidence");
        let endorsements_bytes = read_test_file("tests/data/dcap.endorsements");
        let metrics = attestation_metrics(&evidence_bytes, &endorsements_bytes).unwrap();
        // 2023-02-17 21:56:09 UTC
        assert_eq!(
            *metrics.get("tcb_info_expiration_ts").unwrap(),
            1676670969_i64
        );
        // May 21 10:50:10 2018 GMT
        assert_eq!(
            *metrics.get("tcb_signer_not_before_ts").unwrap(),
            1526899810_i64
        );
        // May 21 10:50:10 2025 GMT
        assert_eq!(
            *metrics.get("tcb_signer_not_after_ts").unwrap(),
            1747824610_i64
        );
    }

    #[test]
    fn test_verify_remote_attestation_expired_attestation() {
        let current_time: SystemTime =
            SystemTime::UNIX_EPOCH + Duration::from_millis(1652744306000);

        let evidence_bytes = read_test_file("tests/data/dcap-expired.evidence");
        let endorsements_bytes = read_test_file("tests/data/dcap-expired.endorsements");

        assert!(verify_remote_attestation(
            evidence_bytes.as_ref(),
            endorsements_bytes.as_ref(),
            &EXPECTED_MRENCLAVE,
            ACCEPTED_SW_ADVISORIES,
            current_time,
        )
        .is_err());
    }

    #[test]
    fn debug_flag() {
        let mut builder = FakeAttestation::builder();
        builder
            .uevidence
            .quote
            .quote_body
            .report_body
            .sgx_attributes[0] |= 0x2;
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn tcb_fmspc_mismatch() {
        let mut builder = FakeAttestation::builder();
        builder.uendorsements.tcb_info.fmspc = [0; 6];
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn tcb_pceid_mismatch() {
        let mut builder = FakeAttestation::builder();
        builder.uendorsements.tcb_info.pce_id = [0, 1];
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn bad_vendor_id() {
        let mut builder = FakeAttestation::builder();
        builder.uevidence.quote.quote_body.qe_vendor_id =
            *uuid::uuid!("00000000-0000-0000-0000-000000000000").as_bytes();
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn bad_mrsigner() {
        let mut builder = FakeAttestation::builder();
        builder.uevidence.quote.support.qe_report_body.mrsigner = [0; 32];
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn check_attributes() {
        fn attribute_comp(mask: [u8; 16], qe_id: [u8; 16], reported: [u8; 16]) -> bool {
            let mut builder = FakeAttestation::builder();
            builder
                .uevidence
                .quote
                .support
                .qe_report_body
                .sgx_attributes = reported;
            builder.uendorsements.qe_id_info.attributes = qe_id;
            builder.uendorsements.qe_id_info.attributes_mask = mask;
            builder.sign().attest().is_ok()
        }
        fn fill(n: u8) -> [u8; 16] {
            (0..n).collect::<Vec<_>>().try_into().unwrap()
        }
        // (mask & reported) == target
        assert!(attribute_comp([0x00; 16], [0x00; 16], [0xFF; 16]));
        assert!(attribute_comp([0xFF; 16], [0x0F; 16], [0x0F; 16]));
        assert!(attribute_comp([0x0F; 16], [0x0A; 16], [0x7A; 16]));
        assert!(attribute_comp([0x07; 16], [0x05; 16], [0xFD; 16]));
        assert!(attribute_comp([0x77; 16], [0x55; 16], [0xDD; 16]));
        assert!(attribute_comp([0xFF; 16], fill(16), fill(16)));

        // (mask & reported) != target
        assert!(!attribute_comp([0x00; 16], [0xFF; 16], [0xFF; 16]));
        assert!(!attribute_comp([0x07; 16], [0x0F; 16], [0x0F; 16]));
        assert!(!attribute_comp([0xF0; 16], [0xB0; 16], [0xC0; 16]));
        assert!(!attribute_comp([0x07; 16], [0x0A; 16], [0x7A; 16]));
        assert!(!attribute_comp([0xFD; 16], fill(16), fill(16)));
    }

    #[test]
    fn check_miscselct() {
        fn miscselect_comp(mask: u32, qe_id: u32, reported: u32) -> bool {
            let mut builder = FakeAttestation::builder();
            builder.uevidence.quote.support.qe_report_body.miscselect = reported.into();
            builder.uendorsements.qe_id_info.miscselect = qe_id.into();
            builder.uendorsements.qe_id_info.miscselect_mask = mask.into();
            builder.sign().attest().is_ok()
        }
        // (mask & reported) == target
        assert!(miscselect_comp(0x00000000, 0x0000000000, 0xFFFFFFFF));
        assert!(miscselect_comp(0x0123ABCD, 0x0123ABCD, 0xFFFFFFFF));
        assert!(miscselect_comp(0xFFFFFFFF, 0x0123ABCD, 0x0123ABCD));
        assert!(miscselect_comp(0xFFFFFFFF, 0x0123ABCD, 0x0123ABCD));
        assert!(miscselect_comp(0x77770000, 0x55550000, 0xDDDDFFFF));

        // (mask & reported) != target
        assert!(!miscselect_comp(0x00000000, 0x0000000001, 0x000000000));
        assert!(!miscselect_comp(0x000000CC, 0x00000000FF, 0x0000000FF));
        assert!(!miscselect_comp(0x000000FF, 0x00000000DD, 0x0000000FF));
        assert!(!miscselect_comp(0x070000FF, 0x00000000DD, 0x070000DD));
    }

    #[test]
    fn qe_id_valid_tcb_level() {
        let mut builder = FakeAttestation::builder();
        let revoked_level = QeTcbLevel::from_parts(QeTcbStatus::OutOfDate, 2);
        let new_level = QeTcbLevel::from_parts(QeTcbStatus::UpToDate, 4);
        builder.uendorsements.qe_id_info.tcb_levels = vec![new_level, revoked_level];
        builder.uevidence.quote.support.qe_report_body.isvsvn = 5u16.into();
        builder.sign().attest().unwrap();
    }

    #[test]
    fn qe_id_unknown() {
        let mut builder = FakeAttestation::builder();
        let level = QeTcbLevel::from_parts(QeTcbStatus::Revoked, 4);
        builder.uendorsements.qe_id_info.tcb_levels = vec![level];
        builder.uevidence.quote.support.qe_report_body.isvsvn = 3u16.into();
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn qe_id_outdated_tcb_level() {
        let mut builder = FakeAttestation::builder();
        let revoked_level = QeTcbLevel::from_parts(QeTcbStatus::OutOfDate, 0);
        let new_level = QeTcbLevel::from_parts(QeTcbStatus::Revoked, 4);
        builder.uendorsements.qe_id_info.tcb_levels = vec![new_level, revoked_level];
        builder.uevidence.quote.support.qe_report_body.isvsvn = 1u16.into();
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn qe_id_revoked_tcb_level() {
        let mut builder = FakeAttestation::builder();
        let revoked_level = QeTcbLevel::from_parts(QeTcbStatus::Revoked, 3);
        let new_level = QeTcbLevel::from_parts(QeTcbStatus::UpToDate, 4);
        builder.uendorsements.qe_id_info.tcb_levels = vec![new_level, revoked_level];
        builder.uevidence.quote.support.qe_report_body.isvsvn = 3u16.into();
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn revoked_pck() {
        let mut builder = FakeAttestation::builder();
        let to_revoke = builder.signing_info.pck_chain[0]
            .x509
            .serial_number()
            .to_bn()
            .unwrap();
        builder.signing_info.revoke_from_pck(to_revoke);
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn revoked_other_pck() {
        let mut builder = FakeAttestation::builder();
        // revoke some other certificate
        builder
            .signing_info
            .revoke_from_pck(BigNum::from_u32(0u32).unwrap());
        builder.sign().attest().unwrap();
    }

    #[test]
    fn revoked_other_root() {
        let mut builder = FakeAttestation::builder();
        // revoke some other certificate
        builder
            .signing_info
            .revoke_from_root(BigNum::from_u32(0u32).unwrap());
        builder.sign().attest().unwrap();
    }

    #[test]
    fn revoked_tcb_signer() {
        let mut builder = FakeAttestation::builder();
        let to_revoke = builder.signing_info.tcb_issuer_chain[0]
            .x509
            .serial_number()
            .to_bn()
            .unwrap();
        builder.signing_info.revoke_from_root(to_revoke);
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn revoked_qe_id_signer() {
        let mut builder = FakeAttestation::builder();
        let to_revoke = builder.signing_info.qe_id_issuer_chain[0]
            .x509
            .serial_number()
            .to_bn()
            .unwrap();
        builder.signing_info.revoke_from_root(to_revoke);
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn v2_tcb_level() {
        let mut builder = FakeAttestation::builder();

        // identical tcb levels, just using the TCB v2 format (which comes from the PCS v3 API)
        builder.uendorsements.tcb_info.tcb_levels = builder
            .uendorsements
            .tcb_info
            .tcb_levels
            .iter()
            .map(|level| {
                TcbLevel::from_parts(
                    TcbInfoVersion::V2,
                    level.tcb.components(),
                    level.tcb.pcesvn(),
                    level.tcb_status,
                    Vec::new(),
                )
            })
            .collect();
        builder.sign().attest().unwrap();
    }

    #[test]
    fn unsupported_tcb_level() {
        let mut level_compsvn = [0u8; 16];
        level_compsvn[0] = 1u8;

        let mut builder = FakeAttestation::builder();
        builder.uendorsements.tcb_info.tcb_levels = vec![TcbLevel::from_parts(
            TcbInfoVersion::V3,
            level_compsvn,
            0,
            TcbStatus::SWHardeningNeeded,
            Vec::new(),
        )];
        builder.uevidence.quote.support.pck_extension.tcb.compsvn = [0u8; 16];
        builder.uevidence.quote.support.pck_extension.tcb.pcesvn = 0;
        // should fail, there is no tcb level that this pck is greater than
        assert!(builder.sign().attest().is_err());
    }

    #[test]
    fn sw_hardening_needed() {
        let expected_ids = vec!["INTEL-SA-1234".to_owned()];
        let mut level_compsvn = [0u8; 16];
        level_compsvn[0] = 1u8;

        let mut builder = FakeAttestation::builder();
        builder.uendorsements.tcb_info.tcb_levels = vec![TcbLevel::from_parts(
            TcbInfoVersion::V3,
            level_compsvn,
            0,
            TcbStatus::SWHardeningNeeded,
            expected_ids.clone(),
        )];
        builder.uevidence.quote.support.pck_extension.tcb.compsvn = [0; 16];
        builder.uevidence.quote.support.pck_extension.tcb.compsvn[0] = 1u8;
        builder.uevidence.quote.support.pck_extension.tcb.pcesvn = 0;
        let attest = builder.sign().attest().unwrap();
        // should verify, but return bad advisory ids
        assert!(
            matches!(attest.tcb_standing, TcbStanding::SWHardeningNeeded {advisory_ids} if advisory_ids == expected_ids)
        )
    }
}
