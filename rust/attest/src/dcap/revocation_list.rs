//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::dcap::{Error, Expireable, Result};
use boring::nid::Nid;
use boring::x509::crl::{X509CRLRef, X509CRL};
use std::collections::HashSet;
use std::time::SystemTime;

#[derive(Debug)]
pub(crate) struct RevocationList {
    crl: X509CRL,
}

impl Expireable for RevocationList {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        crate::util::system_time_to_asn1_time(timestamp)
            .ok()
            .zip(self.crl.next_update())
            .and_then(|(now, next_update)| now.compare(next_update).ok())
            .map(|order| order.is_lt())
            .unwrap_or(false)
    }
}

impl RevocationList {
    pub fn from_der_data(data: &[u8]) -> Result<RevocationList> {
        let crl = X509CRL::from_der(data)?;

        // all RFC 5280 CRLs should have authority key
        // identifiers and a CRL number
        let nids: HashSet<Nid> = crl
            .extensions()
            .map(|extensions| {
                extensions
                    .iter()
                    .map(|extension| extension.object().nid())
                    .collect()
            })
            .unwrap_or_else(HashSet::new);

        if !nids.contains(&Nid::AUTHORITY_KEY_IDENTIFIER) || !nids.contains(&Nid::CRL_NUMBER) {
            return Err(Error::new("CRL missing required extension"));
        }

        Ok(RevocationList { crl })
    }

    #[cfg(test)]
    pub fn from_crl(crl: X509CRL) -> RevocationList {
        RevocationList { crl }
    }

    pub fn crl(&self) -> &X509CRLRef {
        self.crl.as_ref()
    }
}
