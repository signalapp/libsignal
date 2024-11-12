//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

/// The addres of a remote host, either IP or DNS domain name.
///
/// This is similar to, and convertible to/from, [`url::Host`], but it supports
/// parsing from a wider range of formats (namely un-bracketed IPv6 addresses).
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub enum Host<S> {
    /// An IPv4 or IPv6 address.
    Ip(IpAddr),
    /// A DNS domain name.
    Domain(S),
}

impl<S> Host<S> {
    pub fn as_ref(&self) -> Host<&S> {
        match self {
            Host::Domain(domain) => Host::Domain(domain),
            Host::Ip(ip) => Host::Ip(*ip),
        }
    }

    pub fn as_deref<T: ?Sized>(&self) -> Host<&T>
    where
        S: std::ops::Deref<Target = T>,
    {
        match self {
            Host::Ip(ip) => Host::Ip(*ip),
            Host::Domain(domain) => Host::Domain(domain),
        }
    }

    /// Try to parse as an IP address, otherwise assume the input is a domain name.
    ///
    /// This doesn't validate as extensively as [`url::Host::parse`] does, but
    /// we don't need anything that heavy-weight.
    pub fn parse_as_ip_or_domain<'s>(s: &'s str) -> Self
    where
        S: From<&'s str>,
    {
        // If the input is a stringified IP address, use that as the host.
        // Otherwise assume the input is a domain name.
        if let Ok(ip) = IpAddr::from_str(s) {
            return Self::Ip(ip);
        }
        if let Some(ip) = s
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|s| Ipv6Addr::from_str(s).ok())
        {
            return Self::Ip(ip.into());
        }

        Self::Domain(s.into())
    }

    /// Transforms the `Domain` variant with the provided function.
    ///
    /// Like `Option::map`; this produces a new `Host` by applying `f` to the
    /// `Domain` value if there is one, otherwise keeping the `Ip` value
    /// untouched.
    pub fn map_domain<T>(self, f: impl FnOnce(S) -> T) -> Host<T> {
        match self {
            Host::Ip(ip_addr) => Host::Ip(ip_addr),
            Host::Domain(d) => Host::Domain(f(d)),
        }
    }
}

impl<S> From<Host<S>> for url::Host<S> {
    fn from(host: Host<S>) -> Self {
        match host {
            Host::Ip(IpAddr::V4(ip)) => url::Host::Ipv4(ip),
            Host::Ip(IpAddr::V6(ip)) => url::Host::Ipv6(ip),
            Host::Domain(domain) => url::Host::Domain(domain),
        }
    }
}

impl<S> From<IpAddr> for Host<S> {
    fn from(value: IpAddr) -> Self {
        Self::Ip(value)
    }
}

impl<S> From<url::Host<S>> for Host<S> {
    fn from(value: url::Host<S>) -> Self {
        match value {
            url::Host::Domain(domain) => Self::Domain(domain),
            url::Host::Ipv4(ip) => Self::Ip(ip.into()),
            url::Host::Ipv6(ip) => Self::Ip(ip.into()),
        }
    }
}

impl<S: AsRef<str>> Display for Host<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        url::Host::from(self.as_ref()).fmt(f)
    }
}
