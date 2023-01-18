//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use boring::ec::EcKey;
use boring::pkey::Public;
use boring::stack::{Stack, Stackable};
use boring::x509::crl::X509CRLRef;
use boring::x509::store::X509StoreRef;
use boring::x509::{X509StoreContext, X509VerifyResult, X509};

use std::time::SystemTime;

use crate::dcap::{Error, Expireable, Result};

#[derive(Debug)]
pub(crate) struct CertChain {
    /// X509 certs ordered from leaf to root
    /// Each cert should be issued by the previous
    /// cert in the chain
    certs: Vec<X509>,
}

impl CertChain {
    pub fn from_pem_data(data: &[u8]) -> Result<CertChain> {
        let mut certs = X509::stack_from_pem(data)?;

        if certs.is_empty() {
            return Err(Error::new("empty chain"));
        }
        Self::sort(&mut certs)?;

        Ok(CertChain { certs })
    }

    pub fn leaf(&self) -> &X509 {
        &self.certs[0]
    }

    pub fn leaf_pub_key(&self) -> Result<EcKey<Public>> {
        self.leaf()
            .public_key()
            .and_then(|pkey| pkey.ec_key())
            .map_err(|e| Error::from(e).context("leaf_pub_key"))
    }

    pub fn root(&self) -> &X509 {
        self.certs.last().expect("certs must not be empty")
    }

    /// Validate that the leaf of this certificate chain is eventually rooted in
    /// a certificate in the provided trust store.
    ///
    /// # Arguments
    ///
    /// * `trust` An X509Store containing trusted certificates and CRLs. If CRLs
    ///           are present the store should be configured to validate crls
    /// * `crls`  Additional CRLs that are not trusted, and must be issued by
    ///           a certificate in this certificate chain rooted in the trust
    ///           store
    ///
    pub fn validate_chain(&self, trust: &X509StoreRef, crls: &[&X509CRLRef]) -> Result<()> {
        let crl_stack = Self::stack(crls.iter().map(|&crl| crl.to_owned()))
            .map_err(|e| Error::from(e).context("crl stack"))?;
        let cert_stack = Self::stack(self.certs.iter().cloned())
            .map_err(|e| Error::from(e).context("cert stack"))?;
        let mut ctx = X509StoreContext::new().expect("can allocate a fresh X509StoreContext");
        let verified = ctx
            .init(trust, self.leaf(), &cert_stack, |c| {
                c.verify_cert_with_crls(crl_stack)
            })
            .unwrap_or(false);
        if !verified {
            #[cfg(not(fuzzing))]
            return Err(Error::new(format!(
                "invalid certificate: {:?}",
                ctx.error()
            )));
        }

        Ok(())
    }

    /// Converts the iterator into a stack, preserving the iterator's original order
    fn stack<T, I>(ts: I) -> std::result::Result<Stack<T>, boring::error::ErrorStack>
    where
        T: Stackable,
        I: IntoIterator<Item = T>,
    {
        let mut stack = Stack::new().expect("can always create a new stack");
        for t in ts {
            stack.push(t)?;
        }
        Ok(stack)
    }

    /// Sorts the certificates from leaf->root, failing
    /// if the chain has any missing or extra links
    fn sort(certs: &mut [X509]) -> Result<()> {
        fn to_error() -> Error {
            Error::new("Invalid certificate chain")
        }

        // move the root into the last position
        let root_pos = certs
            .iter()
            .rposition(|c| c.issued(c) == X509VerifyResult::OK)
            .ok_or_else(to_error)?;
        let end_pos = certs.len() - 1;
        certs.swap(end_pos, root_pos);

        // searches backwards so the common case where
        // the chain is already ordered is linear
        for curr in (1..certs.len()).rev() {
            let issuer = &certs[curr];
            // starting at curr - 1, find the cert issued by curr
            let nxt_pos = certs[0..curr]
                .iter()
                .rposition(|c| issuer.issued(c) == X509VerifyResult::OK)
                .ok_or_else(to_error)?;
            certs.swap(curr - 1, nxt_pos);
        }
        Ok(())
    }
}

impl Expireable for CertChain {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        let asn1_timestamp = crate::util::system_time_to_asn1_time(timestamp);

        if asn1_timestamp.is_err() {
            return false;
        }

        let asn1_timestamp = asn1_timestamp.unwrap();

        self.certs.iter().all(|cert| -> bool {
            cert.not_before()
                .compare(&asn1_timestamp)
                .map(|order| order.is_le())
                .unwrap_or(false)
                && cert
                    .not_after()
                    .compare(&asn1_timestamp)
                    .map(|order| order.is_ge())
                    .unwrap_or(false)
        })
    }
}

#[cfg(test)]
/// Utilities for creating test certificates / crls
pub mod testutil {
    use crate::dcap::cert_chain::CertChain;
    use boring::asn1::{Asn1Integer, Asn1IntegerRef, Asn1Time};
    use boring::bn::{BigNum, MsbOption};
    use boring::ec::{EcGroup, EcKey};
    use boring::hash::MessageDigest;
    use boring::nid::Nid;
    use boring::pkey::{PKey, Private};
    use boring::x509::crl::{X509CRLBuilder, X509Revoked, X509CRL};
    use boring::x509::extension::BasicConstraints;
    use boring::x509::{X509Name, X509};
    use std::borrow::Borrow;

    /// generate EC private key
    fn pkey() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    impl CertChain {
        pub(crate) fn from_certs(certs: Vec<X509>) -> CertChain {
            CertChain { certs }
        }
    }

    pub(crate) fn serial_number() -> Asn1Integer {
        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    }

    #[derive(Clone)]
    pub(crate) struct TestCert {
        pub pkey: PKey<Private>,
        pub x509: X509,
    }

    impl TestCert {
        /// Create a self-issued X509/key pair
        pub fn self_issued(cn: &str) -> TestCert {
            Self::new(None, cn)
        }

        /// Create an X509/key pair signed by this certificate
        pub fn issue(&self, cn: &str) -> TestCert {
            Self::new(Some(self), cn)
        }

        /// creates a test x509/key pair, self-signed if no issuer
        pub fn new(issuer: Option<&TestCert>, cn: &str) -> TestCert {
            let pkey = pkey();

            let mut name = X509Name::builder().unwrap();
            name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
            let name = name.build();

            let mut builder = X509::builder().unwrap();
            let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
            builder.append_extension(basic_constraints).unwrap();

            builder.set_version(2).unwrap();
            builder.set_subject_name(&name).unwrap();
            builder.set_pubkey(&pkey).unwrap();
            builder.set_serial_number(&serial_number()).unwrap();
            builder
                .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::days_from_now(365).unwrap())
                .unwrap();

            let issuer_name = issuer.map(|c| c.x509.subject_name()).unwrap_or(&name);
            builder.set_issuer_name(issuer_name).unwrap();

            let signer = issuer.map(|c| &c.pkey).unwrap_or(&pkey);
            builder.sign(signer, MessageDigest::sha256()).unwrap();

            TestCert {
                x509: builder.build(),
                pkey,
            }
        }

        pub fn empty_crl(&self) -> X509CRL {
            self.crl::<Asn1IntegerRef>(&[])
        }

        pub fn crl<T>(&self, revoked: &[T]) -> X509CRL
        where
            T: Borrow<Asn1IntegerRef>,
        {
            let mut builder = X509CRLBuilder::new().unwrap();
            builder.set_issuer_name(self.x509.subject_name()).unwrap();
            builder
                .set_last_update(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            builder
                .set_next_update(&Asn1Time::days_from_now(30).unwrap())
                .unwrap();
            for sn in revoked {
                builder
                    .add_revoked(
                        X509Revoked::from_parts(sn.borrow(), &Asn1Time::days_from_now(0).unwrap())
                            .unwrap(),
                    )
                    .unwrap();
            }
            builder.sign(&self.pkey, MessageDigest::sha256()).unwrap();
            builder.build()
        }

        /// Create a chain of test certificates issued by this certificate
        pub fn issue_chain(&self, len: usize) -> Vec<TestCert> {
            let mut vs = Vec::new();
            vs.push(self.clone());
            for i in 0..len {
                vs.push(vs.last().unwrap().issue(&i.to_string()));
            }
            vs.reverse();
            vs
        }

        /// Create a chain of test certificates with a self-signed root
        ///
        /// Ordered from leaf to root
        pub fn chain(len: usize) -> Vec<TestCert> {
            let mut vs = Vec::new();
            for i in 0..len {
                vs.push(TestCert::new(vs.last(), &i.to_string()))
            }
            vs.reverse();
            vs
        }
    }

    /// Creates a certificate chain of the specified length
    pub(crate) fn chain(len: usize) -> Vec<X509> {
        TestCert::chain(len).into_iter().map(|p| p.x509).collect()
    }

    pub(crate) fn cert_chain(len: usize) -> CertChain {
        CertChain { certs: chain(len) }
    }
}

#[cfg(test)]
mod test {
    use super::testutil::*;
    use super::*;
    use boring::nid::Nid;
    use boring::x509::store::{X509Store, X509StoreBuilder};
    use boring::x509::verify::X509VerifyFlags;
    use boring::x509::X509Ref;

    fn names(certs: &[X509]) -> Vec<String> {
        certs
            .iter()
            .map(|c| {
                c.subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .unwrap()
                    .data()
                    .as_utf8()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn sort_reversed() {
        let mut chain = chain(5);
        let expected = names(&chain);

        chain.reverse();
        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_ordered() {
        let mut chain = chain(5);
        let expected = names(&chain);

        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_unordered() {
        let mut chain = chain(5);
        let expected = names(&chain);
        chain.swap(4, 2);
        chain.swap(0, 3);
        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_small() {
        let mut chain = chain(2);
        let expected = names(&chain);
        chain.reverse();

        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_singleton() {
        let mut chain = chain(1);
        let expected = names(&chain);
        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    fn trust_store(root: &X509Ref, crl: Option<&X509CRLRef>) -> X509Store {
        let mut store_bldr = X509StoreBuilder::new().expect("Could not allocate x509 store");
        if let Some(crl) = crl {
            store_bldr
                .param_mut()
                .set_flags(
                    X509VerifyFlags::CRL_CHECK
                        | X509VerifyFlags::CRL_CHECK_ALL
                        | X509VerifyFlags::X509_STRICT,
                )
                .unwrap();
            store_bldr.add_crl(crl.to_owned()).unwrap();
        }
        store_bldr.add_cert(root.to_owned()).unwrap();
        store_bldr.build()
    }

    #[test]
    fn validate_valid_chain() {
        let cert_chain = CertChain { certs: chain(4) };
        let trust = trust_store(cert_chain.root(), None);
        cert_chain
            .validate_chain(&trust, &[])
            .expect("should validate");
    }

    #[test]
    fn validate_invalid_chain() {
        let mut c = chain(4);
        let trust = trust_store(c.last().unwrap(), None);
        c.remove(2); // delete an intermediate certificate
        let cert_chain = CertChain { certs: c };
        assert!(cert_chain.validate_chain(&trust, &[]).is_err())
    }

    #[test]
    fn validate_revoked_from_root() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().crl(&[c[1].x509.serial_number()]);
        let intermediate_crl = c[1].empty_crl();
        let trust = trust_store(&c.last().unwrap().x509, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.into_iter().map(|p| p.x509).collect(),
        };
        assert!(cert_chain
            .validate_chain(&trust, &[&intermediate_crl])
            .is_err())
    }

    #[test]
    fn validate_revoked_from_intermediate() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().empty_crl();
        let intermediate_crl = c[1].crl(&[c[0].x509.serial_number()]);
        let trust = trust_store(&c.last().unwrap().x509, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.into_iter().map(|p| p.x509).collect(),
        };
        assert!(cert_chain
            .validate_chain(&trust, &[&intermediate_crl])
            .is_err())
    }

    #[test]
    fn validate_other_revoked() {
        let c = TestCert::chain(3);
        // revoke some random serial numbers
        let root_crl = c.last().unwrap().crl(&[serial_number()]);
        let intermediate_crl = c[1].crl(&[serial_number()]);
        let trust = trust_store(&c.last().unwrap().x509, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.into_iter().map(|p| p.x509).collect(),
        };
        cert_chain
            .validate_chain(&trust, &[&intermediate_crl])
            .expect("should validate");
    }

    #[test]
    fn validate_no_revoked() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().empty_crl();
        let intermediate_crl = c[1].empty_crl();
        let trust = trust_store(&c.last().unwrap().x509, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.into_iter().map(|p| p.x509).collect(),
        };
        cert_chain
            .validate_chain(&trust, &[&intermediate_crl])
            .expect("should validate");
    }
}
