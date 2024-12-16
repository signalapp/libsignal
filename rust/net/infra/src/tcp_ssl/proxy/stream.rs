//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_boring_signal::SslStream;

use crate::tcp_ssl::proxy::socks::SocksStream;
use crate::Connection;

#[derive(Debug)]
#[pin_project(project = ProxyStreamProj)]
pub enum ProxyStream {
    Tls(#[pin] SslStream<TcpStream>),
    Tcp(#[pin] TcpStream),
    Socks(#[pin] SocksStream),
}

impl From<SslStream<TcpStream>> for ProxyStream {
    fn from(value: SslStream<TcpStream>) -> Self {
        Self::Tls(value)
    }
}

impl From<TcpStream> for ProxyStream {
    fn from(value: TcpStream) -> Self {
        Self::Tcp(value)
    }
}

impl From<SocksStream> for ProxyStream {
    fn from(value: SocksStream) -> Self {
        Self::Socks(value)
    }
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            ProxyStreamProj::Tls(tls) => tls.poll_read(cx, buf),
            ProxyStreamProj::Tcp(tcp) => tcp.poll_read(cx, buf),
            ProxyStreamProj::Socks(socks) => socks.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.project() {
            ProxyStreamProj::Tls(tls) => tls.poll_write(cx, buf),
            ProxyStreamProj::Tcp(tcp) => tcp.poll_write(cx, buf),
            ProxyStreamProj::Socks(socks) => socks.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project() {
            ProxyStreamProj::Tls(tls) => tls.poll_flush(cx),
            ProxyStreamProj::Tcp(tcp) => tcp.poll_flush(cx),
            ProxyStreamProj::Socks(socks) => socks.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project() {
            ProxyStreamProj::Tls(tls) => tls.poll_shutdown(cx),
            ProxyStreamProj::Tcp(tcp) => tcp.poll_shutdown(cx),
            ProxyStreamProj::Socks(socks) => socks.poll_shutdown(cx),
        }
    }
}

impl Connection for ProxyStream {
    fn transport_info(&self) -> crate::TransportInfo {
        match self {
            ProxyStream::Tls(ssl_stream) => ssl_stream.transport_info(),
            ProxyStream::Tcp(tcp_stream) => tcp_stream.transport_info(),
            ProxyStream::Socks(either) => either.transport_info(),
        }
    }
}
