//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use auto_enums::enum_derive;
use tokio::net::TcpStream;
use tokio_boring_signal::SslStream;

use crate::tcp_ssl::proxy::https::HttpProxyStream;
use crate::tcp_ssl::proxy::socks::SocksStream;
use crate::Connection;

#[derive(Debug, derive_more::From)]
#[enum_derive(tokio1::AsyncRead, tokio1::AsyncWrite)]
pub enum ProxyStream {
    Tls(SslStream<TcpStream>),
    Tcp(TcpStream),
    Socks(SocksStream<TcpStream>),
    Http(HttpProxyStream),
}

impl Connection for ProxyStream {
    fn transport_info(&self) -> crate::TransportInfo {
        match self {
            ProxyStream::Tls(ssl_stream) => ssl_stream.transport_info(),
            ProxyStream::Tcp(tcp_stream) => tcp_stream.transport_info(),
            ProxyStream::Socks(either) => either.transport_info(),
            ProxyStream::Http(http) => http.transport_info(),
        }
    }
}
