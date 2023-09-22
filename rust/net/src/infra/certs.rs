//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use boring::error::ErrorStack;
use boring::x509::store::{X509Store, X509StoreBuilder};
use boring::x509::X509;

use lazy_static::lazy_static;
use rustls_native_certs::Certificate;

lazy_static! {
    static ref NATIVE_CERTS: Vec<Certificate> =
        rustls_native_certs::load_native_certs().expect("can load native certificates");
}

const SIGNAL_ROOT_CERT_DER: &[u8] = include_bytes!("../../res/signal.cer");

#[derive(thiserror::Error, Debug, displaydoc::Display)]
pub enum Error {
    /// Bad certificate DER
    BadDer,
}

impl From<ErrorStack> for Error {
    fn from(_value: ErrorStack) -> Self {
        Self::BadDer
    }
}

#[derive(Debug, Clone, Default)]
pub enum RootCertificates {
    #[default]
    Native,
    Signal,
    FromDer(Vec<u8>),
    Composite(Vec<RootCertificates>),
}

impl RootCertificates {
    fn load(&self) -> Result<Vec<X509>, Error> {
        fn from_der(der: &[u8]) -> Result<X509, Error> {
            X509::from_der(der).map_err(From::from)
        }
        fn singleton(x509: X509) -> Vec<X509> {
            vec![x509]
        }
        match self {
            RootCertificates::Native => NATIVE_CERTS.iter().map(|cert| from_der(&cert.0)).collect(),
            RootCertificates::FromDer(der) => from_der(der).map(singleton),
            RootCertificates::Signal => from_der(SIGNAL_ROOT_CERT_DER).map(singleton),
            RootCertificates::Composite(vec) => vec
                .iter()
                .map(|cert| cert.load())
                .collect::<Result<Vec<Vec<X509>>, Error>>()
                .map(|vv| vv.into_iter().flatten().collect()),
        }
    }
}

impl TryInto<X509Store> for RootCertificates {
    type Error = Error;

    fn try_into(self) -> Result<X509Store, Self::Error> {
        let mut store_builder = X509StoreBuilder::new().expect("can make store");
        for x509 in self.load()? {
            store_builder.add_cert(x509).expect("can add cert");
        }
        Ok(store_builder.build())
    }
}
