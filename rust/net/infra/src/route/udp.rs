//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use tokio::net::UdpSocket;

use crate::route::Connector;

pub struct StatelessUdpConnector;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UdpRoute<Addr> {
    pub address: Addr,
    pub port: NonZeroU16,
}

impl Connector<UdpRoute<IpAddr>, ()> for StatelessUdpConnector {
    type Connection = UdpSocket;
    type Error = std::io::Error;

    async fn connect_over(
        &self,
        (): (),
        route: UdpRoute<IpAddr>,
        _log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let UdpRoute { address, port } = route;

        let local_addr = match &address {
            IpAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect((address, port.into())).await?;
        Ok(socket)
    }
}
