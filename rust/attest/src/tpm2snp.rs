//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::time::SystemTime;

use boring::pkey::{PKey, Public};
use boring::rsa::Rsa;
use boring::x509::store::X509StoreBuilder;
use boring::x509::X509;
use prost::Message;

use crate::cert_chain::{self, CertChain};
use crate::enclave::{Claims, Error, Handshake, Result, UnvalidatedHandshake};
use crate::expireable::Expireable as _;
use crate::proto::{svr, svr3};
use crate::svr2::expected_raft_config;

use crate::constants::TPM2SNP_EXPECTED_PCRS;

mod snp;
mod tpm2;

pub(crate) use tpm2::{Error as Tpm2Error, PcrMap};

const GOOG_AKCERT_ROOT_PEM: &[u8] = include_bytes!("../res/goog_akcert_root.pem");

pub fn new_handshake(enclave: &[u8], attestation_msg: &[u8], now: SystemTime) -> Result<Handshake> {
    let expected_raft_config = expected_raft_config(enclave, None)?;
    let handshake_start = svr::ClientHandshakeStart::decode(attestation_msg)?;
    Handshake::for_tpm2snp(
        enclave,
        &handshake_start.evidence,
        &handshake_start.endorsement,
        now,
    )?
    .validate(expected_raft_config)
}

impl Handshake {
    fn for_tpm2snp(
        enclave: &[u8],
        evidence: &[u8],
        endorsements: &[u8],
        now: SystemTime,
    ) -> Result<UnvalidatedHandshake> {
        let evidence = svr3::AsnpEvidence::decode(evidence)?;
        let endorsements = svr3::AsnpEndorsements::decode(endorsements)?;
        let attestation_data = attest(enclave, &evidence, &endorsements, now)?;
        let claims = Claims::from_attestation_data(attestation_data)?;
        Handshake::with_claims(claims)
    }
}

fn attest(
    enclave: &[u8],
    evidence: &svr3::AsnpEvidence,
    endorsements: &svr3::AsnpEndorsements,
    now: SystemTime,
) -> Result<svr::AttestationData> {
    attest_with_root(enclave, evidence, endorsements, now, GOOG_AKCERT_ROOT_PEM)
}

fn attest_with_root(
    enclave: &[u8],
    evidence: &svr3::AsnpEvidence,
    endorsements: &svr3::AsnpEndorsements,
    now: SystemTime,
    root_pem: &[u8],
) -> Result<svr::AttestationData> {
    let ak_cert_pk = verify_ak_cert(evidence, endorsements, now, root_pem)?;
    let runtime_pk = verify_snp_report(evidence, endorsements, now)?;
    if !(ak_cert_pk.n() == runtime_pk.n() && ak_cert_pk.e() == runtime_pk.e()) {
        return Err(Error::AttestationDataError {
            reason: "RSA keys mismatch".to_string(),
        });
    }
    let expected_pcrs =
        TPM2SNP_EXPECTED_PCRS
            .get(&enclave)
            .ok_or_else(|| Error::AttestationDataError {
                reason: format!("unknown enclave {:?}", enclave),
            })?;
    let tpm2_report = verify_tpm2_quote(evidence, expected_pcrs)?;
    let attestation_data = tpm2_report.verify_atteststion_data(&evidence.attestation_data)?;
    Ok(svr::AttestationData::decode(attestation_data.as_ref())?)
}

fn verify_ak_cert(
    evidence: &svr3::AsnpEvidence,
    endorsements: &svr3::AsnpEndorsements,
    now: SystemTime,
    root_pem: &[u8],
) -> Result<Rsa<Public>> {
    let akcert = X509::from_der(&evidence.akcert_der).expect("valid cert der");
    let chain = {
        let root = X509::from_pem(root_pem).expect("Invalid root certificate");
        let intermediate = X509::from_der(&endorsements.intermediate_der).expect("valid cert der");
        CertChain::new([akcert.clone(), intermediate, root])?
    };
    let store = {
        let mut builder = X509StoreBuilder::new().expect("can make X509 store");
        builder
            .add_cert(chain.root().clone())
            .expect("can add root cert");
        builder.build()
    };
    chain.validate_chain(&store, &[])?;
    if !chain.valid_at(now) {
        return Err(Error::AttestationDataError {
            reason: "Expired certificate".to_string(),
        });
    }
    akcert
        .public_key()
        .and_then(|pk| pk.rsa())
        .map_err(|_| Error::AttestationDataError {
            reason: "Expect an RSA public key".to_string(),
        })
}

fn verify_snp_report(
    evidence: &svr3::AsnpEvidence,
    endorsements: &svr3::AsnpEndorsements,
    now: SystemTime,
) -> Result<Rsa<Public>> {
    let vcek_cert_public_key = verify_vcek_cert(endorsements, now)?;

    let report = snp::Report::new(&evidence.snp_report)?;
    report.verify(vcek_cert_public_key.clone())?;

    let runtime_data = snp::RuntimeData::new(&evidence.runtime_data)?;
    Ok(runtime_data.verify(report)?)
}

fn verify_vcek_cert(
    endorsements: &svr3::AsnpEndorsements,
    now: SystemTime,
) -> Result<PKey<Public>> {
    let vcek_cert = X509::from_der(&endorsements.vcek_der)?;
    let ask_cert = X509::from_der(&endorsements.ask_der)?;

    let root_cert = [snp::ARK_GENOA_ROOT_PEM, snp::ARK_MILAN_ROOT_PEM]
        .iter()
        .map(|pem| X509::from_pem(pem).expect("Invalid AMD root certificate"))
        .find(|root| root.issued(&ask_cert).is_ok())
        .ok_or_else(|| Error::AttestationDataError {
            reason: "Certificate issuer not trusted".to_string(),
        })?;

    let chain = CertChain::new([vcek_cert.clone(), ask_cert, root_cert.clone()])?;
    let trust_store = {
        let mut builder = X509StoreBuilder::new().expect("can make X509 store");
        builder.add_cert(root_cert).expect("can add root cert");
        builder.build()
    };
    chain.validate_chain(&trust_store, &[])?;
    if chain.valid_at(now) {
        Ok(vcek_cert.public_key()?)
    } else {
        Err(Error::AttestationDataError {
            reason: "Expired certificate".to_string(),
        })
    }
}

impl From<boring::error::ErrorStack> for Error {
    fn from(_err: boring::error::ErrorStack) -> Error {
        Error::AttestationDataError {
            reason: "Invalid certificate".to_string(),
        }
    }
}

impl From<cert_chain::Error> for Error {
    fn from(err: cert_chain::Error) -> Self {
        Error::AttestationDataError {
            reason: err.to_string(),
        }
    }
}

impl From<snp::Error> for Error {
    fn from(err: snp::Error) -> Self {
        Error::AttestationDataError {
            reason: err.to_string(),
        }
    }
}

fn verify_tpm2_quote<'a>(
    evidence: &'a svr3::AsnpEvidence,
    expected_pcrs: &tpm2::PcrMap,
) -> Result<tpm2::Report<'a>> {
    let signature = tpm2::Signature::from_slice(&evidence.sig)?;
    let report = {
        let akcert = X509::from_der(&evidence.akcert_der).expect("can parse akcert der");
        let verified = signature.verify_report(&evidence.msg, &akcert)?;
        tpm2::Report::from_slice(verified)?
    };

    let pcrs = {
        let verified = report.verify_pcrs(&evidence.pcrs)?;
        tpm2::Pcrs::from_slice(verified)?
    };
    pcrs.validate(expected_pcrs)?;

    Ok(report)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::ENCLAVE_ID_SVR3_TPM2SNP_STAGING;
    use std::time::Duration;

    #[test]
    fn full_tpm2snp_attestation() {
        let attestation_data = include_bytes!("../tests/data/tpm2snp_attestation_msg.dat");
        let attestation =
            svr::ClientHandshakeStart::decode(attestation_data.as_slice()).expect("valid protobuf");
        let evidence =
            svr3::AsnpEvidence::decode(attestation.evidence.as_slice()).expect("valid evidence");
        let endorsements = svr3::AsnpEndorsements::decode(attestation.endorsement.as_slice())
            .expect("valid endorsements");
        attest_with_root(
            ENCLAVE_ID_SVR3_TPM2SNP_STAGING,
            &evidence,
            &endorsements,
            SystemTime::UNIX_EPOCH + VALID_TIMESTAMP,
            GOOG_AKCERT_ROOT_PEM,
        )
        .expect("can attest asnp");
    }

    const VALID_TIMESTAMP: Duration = Duration::from_millis(1712946543000);
}
