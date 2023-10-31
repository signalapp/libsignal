//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;

use futures_util::future::BoxFuture;

pub type LookupResult = Vec<IpAddr>;

#[derive(displaydoc::Display, Debug, thiserror::Error)]
pub enum Error {
    /// DNS lookup failed
    LookupFailed,
}

pub type ResolveFn = fn(&str) -> BoxFuture<Result<LookupResult, Error>>;

#[derive(Clone, Debug)]
pub enum DnsResolver {
    Static,
    System,
    GenericAsync(Arc<ResolveFn>),
}

impl DnsResolver {
    pub async fn lookup_ip(&self, host: &str) -> Result<LookupResult, Error> {
        match self {
            DnsResolver::Static => match host {
                "chat.staging.signal.org" => Ok(vec![
                    IpAddr::V4(Ipv4Addr::new(76, 223, 72, 142)),
                    IpAddr::V4(Ipv4Addr::new(3, 248, 206, 115)),
                ]),
                "cdsi.staging.signal.org" => Ok(vec![IpAddr::V4(Ipv4Addr::new(104, 43, 162, 137))]),
                "chat.signal.org" => Ok(vec![
                    IpAddr::V4(Ipv4Addr::new(76, 223, 92, 165)),
                    IpAddr::V4(Ipv4Addr::new(13, 248, 212, 111)),
                ]),
                "cdsi.signal.org" => Ok(vec![IpAddr::V4(Ipv4Addr::new(40, 122, 45, 194))]),
                _ => Err(Error::LookupFailed),
            },
            DnsResolver::GenericAsync(async_resolver) => async_resolver(host).await,
            DnsResolver::System => format!("{}:443", host)
                .to_socket_addrs()
                .map(|addrs| {
                    let c: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
                    c
                })
                .map_err(|_| Error::LookupFailed),
        }
    }
}
