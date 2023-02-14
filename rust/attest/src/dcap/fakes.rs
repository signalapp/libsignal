//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Test-only builders for evidence/endorsements
//! signed by testing certificates
//!
//! # Usage
//! 1. Create a builder with [`FakeAttestation::builder`].
//! 2. Manipulate the default certificates on the enclosed [`SigningInfo`]
//! 3. Manipulate the default evidence/endorsements
//! 4. Create the final evidence/endorsements with [`FakeAttestation::sign`]

use crate::dcap::cert_chain::testutil::TestCert;
use crate::dcap::cert_chain::CertChain;
use crate::dcap::ecdsa::EcdsaSigned;
use crate::dcap::endorsements::SgxEndorsements;
use crate::dcap::evidence::Evidence;
use crate::dcap::revocation_list::RevocationList;
use crate::dcap::{attest_impl, Attestation};
use boring::asn1::{Asn1Integer, Asn1IntegerRef};
use boring::bn::{BigNum, BigNumContext};
use boring::ec::{EcGroup, EcKey, EcKeyRef};
use boring::ecdsa::EcdsaSig;
use boring::hash::{Hasher, MessageDigest};
use boring::nid::Nid;
use boring::pkey::{PKey, Private, Public};
use chrono::Utc;
use lazy_static::lazy_static;
use std::convert::TryFrom;
use std::time::SystemTime;

lazy_static! {
    static ref EVIDENCE_BYTES: Vec<u8> =
        crate::util::testio::read_test_file("tests/data/dcap.evidence");
    static ref ENDORSEMENT_BYTES: Vec<u8> =
        crate::util::testio::read_test_file("tests/data/dcap.endorsements");
}

pub(crate) struct SigningInfo {
    pub root: TestCert,
    pub pck_chain: Vec<TestCert>,
    pub pck_issuer_crl_chain: Vec<TestCert>,
    pub tcb_issuer_chain: Vec<TestCert>,
    pub qe_id_issuer_chain: Vec<TestCert>,
    pub attest_key: EcKey<Private>,
    pub root_revoked: Vec<BigNum>,
    pub pck_revoked: Vec<BigNum>,
}

impl SigningInfo {
    pub fn revoke_from_root(&mut self, revoked: BigNum) {
        self.root_revoked.push(revoked);
    }

    pub fn revoke_from_pck(&mut self, revoked: BigNum) {
        self.pck_revoked.push(revoked);
    }

    fn crl(cert: &TestCert, revoked: &[BigNum]) -> RevocationList {
        let revoked_sns: Vec<Asn1Integer> = revoked
            .iter()
            .map(|sn| sn.to_asn1_integer().unwrap())
            .collect();
        let revoked: Vec<&Asn1IntegerRef> = revoked_sns.iter().map(Asn1Integer::as_ref).collect();
        RevocationList::from_crl(cert.crl(&revoked))
    }

    fn root_crl(&self) -> RevocationList {
        Self::crl(&self.root, &self.root_revoked)
    }

    fn pck_crl(&self) -> RevocationList {
        Self::crl(&self.pck_issuer_crl_chain[0], &self.pck_revoked)
    }

    fn serialize_attest_public_key(&self) -> [u8; 64] {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut xbn = BigNum::new().unwrap();
        let mut ybn = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        self.attest_key
            .public_key()
            .affine_coordinates_gfp(&group, &mut xbn, &mut ybn, &mut ctx)
            .unwrap();
        let mut res = [0u8; 64];
        res[0..32].copy_from_slice(&xbn.to_vec_padded(32).unwrap());
        res[32..].copy_from_slice(&ybn.to_vec_padded(32).unwrap());
        res
    }
}

impl Default for SigningInfo {
    fn default() -> Self {
        let root = TestCert::self_issued("root");
        let pck_chain = root.issue_chain(2);
        assert_eq!(pck_chain.len(), 3);

        // should be the root and the pck intermediate cert
        let pck_issuer_crl_chain = vec![pck_chain[1].clone(), root.clone()];

        // in intel collateral, these are the same, but they could theoretically be different
        let tcb_issuer_chain = root.issue_chain(1);
        let qe_id_issuer_chain = root.issue_chain(1);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let attest_key = EcKey::generate(&group).unwrap();

        Self {
            root,
            pck_chain,
            pck_issuer_crl_chain,
            tcb_issuer_chain,
            qe_id_issuer_chain,
            attest_key,
            root_revoked: Vec::new(),
            pck_revoked: Vec::new(),
        }
    }
}

pub(crate) struct FakeAttestation {
    pub root_key: PKey<Public>,
    pub evidence: Evidence<'static>,
    pub endorsements: SgxEndorsements,
}

impl FakeAttestation {
    /// Create a `[FakeAttestationBuilder]` with unsigned evidence/endorsements
    ///
    /// The initial values of evidence/endorsements are arbitrary but will pass attestation
    /// when signed. To perform a test, manipulate evidence/endorsements
    /// before [`FakeAttestationBuilder::sign`]ing them.
    pub fn builder() -> FakeAttestationBuilder {
        let uevidence = Evidence::try_from(EVIDENCE_BYTES.as_slice()).unwrap();
        let mut uendorsements = SgxEndorsements::try_from(ENDORSEMENT_BYTES.as_slice()).unwrap();
        let signing_info = SigningInfo::default();
        // by default, expire tcb_info/qe_id tomorrow
        let tomorrow = Utc::now() + chrono::Duration::days(1);
        uendorsements.tcb_info.next_update = tomorrow;
        uendorsements.qe_id_info.next_update = tomorrow;
        FakeAttestationBuilder {
            signing_info,
            uevidence,
            uendorsements,
        }
    }

    pub fn attest(self) -> Result<Attestation, super::Error> {
        attest_impl(
            self.evidence,
            self.endorsements,
            &self.root_key,
            SystemTime::now(),
        )
    }
}

pub(crate) struct FakeAttestationBuilder {
    pub signing_info: SigningInfo,

    // unsigned evidence/endorsements
    pub uevidence: Evidence<'static>,
    pub uendorsements: SgxEndorsements,
}

impl FakeAttestationBuilder {
    fn sign_data(data: &[u8], key: &EcKeyRef<Private>) -> EcdsaSig {
        let hash = boring::hash::hash(MessageDigest::sha256(), data).unwrap();
        EcdsaSig::sign(&hash, key).unwrap()
    }

    /// Create Evidence/Endorsements that have the appropriate report signatures, and QE report data
    ///
    /// Note that this will overwrite any manually set. If you'd like to test a corrupt signature,
    /// do it after signing.
    pub fn sign(mut self) -> FakeAttestation {
        self.uevidence.quote.support.attest_pub_key =
            self.signing_info.serialize_attest_public_key();
        self.uevidence
            .quote
            .support
            .qe_report_body
            .sgx_report_data_bytes = [0; 64];
        let hash = {
            let mut h = Hasher::new(MessageDigest::sha256()).unwrap();
            h.update(&self.uevidence.quote.support.attest_pub_key)
                .unwrap();
            h.update(self.uevidence.quote.support.auth_data).unwrap();
            h.finish().unwrap()
        };
        self.uevidence
            .quote
            .support
            .qe_report_body
            .sgx_report_data_bytes[0..32]
            .copy_from_slice(&hash);

        self.uevidence.quote.support.isv_signature =
            Self::sign_data(self.uevidence.quote.data(), &self.signing_info.attest_key);
        self.uevidence.quote.support.qe_report_signature = Self::sign_data(
            self.uevidence.quote.support.data(),
            &self.signing_info.pck_chain[0].pkey.ec_key().unwrap(),
        );

        self.uendorsements.root_crl = self.signing_info.root_crl();
        self.uendorsements.pck_issuer_crl = self.signing_info.pck_crl();
        self.uendorsements.qe_id_issuer_chain = CertChain::from_certs(
            self.signing_info
                .qe_id_issuer_chain
                .into_iter()
                .map(|tc| tc.x509)
                .collect(),
        );
        self.uendorsements.tcb_issuer_chain = CertChain::from_certs(
            self.signing_info
                .tcb_issuer_chain
                .into_iter()
                .map(|tc| tc.x509)
                .collect(),
        );
        self.uendorsements.pck_issuer_crl_chain = CertChain::from_certs(
            self.signing_info
                .pck_issuer_crl_chain
                .into_iter()
                .map(|tc| tc.x509)
                .collect(),
        );
        self.uevidence.quote.support.pck_cert_chain = CertChain::from_certs(
            self.signing_info
                .pck_chain
                .into_iter()
                .map(|tc| tc.x509)
                .collect(),
        );
        FakeAttestation {
            root_key: self.signing_info.root.x509.public_key().unwrap(),
            evidence: self.uevidence,
            endorsements: self.uendorsements,
        }
    }
}
