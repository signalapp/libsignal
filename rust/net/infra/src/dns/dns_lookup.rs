//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use either::Either;
use itertools::Itertools;

use crate::dns::custom_resolver::{CustomDnsResolver, DnsTransport};
use crate::dns::dns_errors::Error;
use crate::dns::lookup_result::LookupResult;
use crate::{dns, DnsSource};

#[derive(Clone, Debug)]
pub struct DnsLookupRequest {
    pub hostname: Arc<str>,
    pub ipv6_enabled: bool,
}

#[async_trait]
pub trait DnsLookup: Debug + Send + Sync {
    async fn dns_lookup(&self, request: DnsLookupRequest) -> dns::Result<LookupResult>;
}

/// Performs DNS lookup using system resolver
#[derive(Debug, Default)]
pub struct SystemDnsLookup;

/// Performs DNS lookup in a map of statically configured, non-expiring entries
#[derive(Debug, Default)]
pub struct StaticDnsMap(pub HashMap<&'static str, LookupResult>);

#[async_trait]
impl DnsLookup for SystemDnsLookup {
    async fn dns_lookup(&self, request: DnsLookupRequest) -> dns::Result<LookupResult> {
        let lookup_result = tokio::net::lookup_host((request.hostname.as_ref(), 443))
            .await
            .map_err(|_| Error::LookupFailed)?;

        let (ipv4s, ipv6s): (Vec<_>, Vec<_>) =
            lookup_result.into_iter().partition_map(|ip| match ip {
                SocketAddr::V4(v4) => Either::Left(*v4.ip()),
                SocketAddr::V6(v6) => Either::Right(*v6.ip()),
            });
        match LookupResult::new(DnsSource::SystemLookup, ipv4s, ipv6s) {
            lookup_result if !lookup_result.is_empty() => Ok(lookup_result),
            _ => Err(Error::LookupFailed),
        }
    }
}

#[async_trait]
impl DnsLookup for StaticDnsMap {
    async fn dns_lookup(&self, request: DnsLookupRequest) -> dns::Result<LookupResult> {
        self.0
            .get(request.hostname.as_ref())
            .ok_or(Error::NoData)
            .cloned()
    }
}

#[async_trait]
impl<T> DnsLookup for CustomDnsResolver<T>
where
    T: DnsTransport<ConnectionParameters: Sync> + Sync + 'static,
{
    async fn dns_lookup(&self, request: DnsLookupRequest) -> dns::Result<LookupResult> {
        self.resolve(request).await
    }
}
