//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::pin::Pin;
use std::task::Poll;

use futures_util::ready;

use crate::TransportInfo;

/// A wrapper around an [`AsyncDuplexStream`](crate::AsyncDuplexStream) with manually-provided
/// [`TransportInfo`].
///
/// Intended for use with wrapper streams that don't expose their underlying stream; the underlying
/// stream's transport info can be captured ahead of time.
#[derive(Debug)]
pub struct StreamWithFixedTransportInfo<T> {
    inner: T,
    transport_info: TransportInfo,
}

impl<T> StreamWithFixedTransportInfo<T> {
    pub fn new(inner: T, transport_info: TransportInfo) -> Self {
        Self {
            inner,
            transport_info,
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for StreamWithFixedTransportInfo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for StreamWithFixedTransportInfo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<T> crate::Connection for StreamWithFixedTransportInfo<T> {
    fn transport_info(&self) -> TransportInfo {
        self.transport_info.clone()
    }
}

#[derive(Debug)]
pub struct WorkaroundWriteBugDuplexStream<T> {
    inner: T,
}

impl<T> WorkaroundWriteBugDuplexStream<T> {
    // This is only used on certain platforms; rather than try to keep track of which precisely, we
    // just silence the warning unconditionally.
    #[allow(dead_code)]
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    fn failed_write_check(
        bytes_supposedly_written: usize,
        size_of_buffers: usize,
    ) -> std::io::Error {
        let error_msg = format!(
            concat!(
                "detected misbehaving write() implementation",
                " (claimed to write {}, but only {} available)",
            ),
            bytes_supposedly_written, size_of_buffers
        );
        // We use WARN here rather than ERROR because it's not a bug in Signal code.
        log::warn!("{}", error_msg);
        std::io::Error::other(error_msg)
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WorkaroundWriteBugDuplexStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WorkaroundWriteBugDuplexStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let bytes_written = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        if bytes_written <= buf.len() {
            return Poll::Ready(Ok(bytes_written));
        }
        Poll::Ready(Err(Self::failed_write_check(bytes_written, buf.len())))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let bytes_written = ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, bufs))?;
        let mut bytes_available = 0;
        for buf in bufs {
            bytes_available += buf.len();
            if bytes_written <= bytes_available {
                return Poll::Ready(Ok(bytes_written));
            }
        }
        Poll::Ready(Err(Self::failed_write_check(
            bytes_written,
            bytes_available,
        )))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<T: crate::Connection> crate::Connection for WorkaroundWriteBugDuplexStream<T> {
    fn transport_info(&self) -> crate::TransportInfo {
        self.inner.transport_info()
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::io::IoSlice;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use boring_signal::ssl::{SslConnector, SslMethod};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::tcp_ssl::testutil::{
        SERVER_CERTIFICATE, SERVER_HOSTNAME, make_http_request_response_over,
        simple_localhost_https_server,
    };

    #[tokio::test]
    async fn correctly_working_stream() {
        let (client, mut server) = tokio::io::duplex(32);

        let echo_task = tokio::spawn(async move {
            let mut buf = [0; 32];
            while let Ok(count) = server.read(&mut buf).await {
                if count == 0 {
                    break;
                }
                server.write_all(&buf[..count]).await.expect("can write");
            }
        });

        let mut client_wrapper = WorkaroundWriteBugDuplexStream::new(client);
        client_wrapper
            .write_all(&[1, 2, 3, 4])
            .await
            .expect("can send");
        let mut buf = [0; 64];
        client_wrapper
            .read_exact(&mut buf[..4])
            .await
            .expect("can receive");
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);

        let (mut client_read, mut client_write) = tokio::io::split(client_wrapper);
        futures_util::try_join!(
            client_write.write_all(&[1; 64]),
            client_read.read_exact(&mut buf[..64]),
        )
        .expect("success");
        assert_eq!(&buf[..64], &[1; 64]);

        let vectored_written = client_write
            .write_vectored(&[
                IoSlice::new(&[2; 16]),
                IoSlice::new(&[2; 16]),
                IoSlice::new(&[2; 16]),
                IoSlice::new(&[2; 16]),
            ])
            .await
            .expect("can write vectored");
        client_read
            .read_exact(&mut buf[..vectored_written])
            .await
            .expect("can read");
        assert_eq!(&buf[..vectored_written], &vec![2; vectored_written]);

        client_write.shutdown().await.expect("can shut down");
        echo_task.await.expect("completes successfully");
        let remaining = client_read.read(&mut buf).await.expect("can read EOF");
        assert_eq!(0, remaining);
    }

    struct BrokenWriteStream {
        constant_return_value: usize,
    }

    impl tokio::io::AsyncWrite for BrokenWriteStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Ok(self.constant_return_value))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn problematic_stream() {
        let mut wrapper = WorkaroundWriteBugDuplexStream::new(BrokenWriteStream {
            constant_return_value: 33,
        });

        let written = wrapper.write(&[0; 64]).await.expect("success");
        assert_eq!(written, 33); // can't tell if this is a problem

        let err = wrapper
            .write(&[0; 32])
            .await
            .expect_err("should have been detected");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("misbehaving write()"));

        let written_vectored = wrapper
            .write_vectored(&[
                IoSlice::new(&[2; 16]),
                IoSlice::new(&[2; 16]),
                IoSlice::new(&[2; 16]),
                IoSlice::new(&[2; 16]),
            ])
            .await
            .expect("success");
        assert_eq!(written_vectored, 33); // can't tell if this is a problem either

        let err_vectored = wrapper
            .write_vectored(&[IoSlice::new(&[2; 16]), IoSlice::new(&[2; 16])])
            .await
            .expect_err("should have been detected");
        assert_eq!(err_vectored.kind(), std::io::ErrorKind::Other);
        assert!(err_vectored.to_string().contains("misbehaving write()"));
    }

    #[tokio::test]
    async fn problematic_stream_causes_ssl_abort() {
        let (addr, server) = simple_localhost_https_server();
        let _server_handle = tokio::spawn(server);

        let mut ssl = SslConnector::builder(SslMethod::tls_client()).expect("valid");
        RootCertificates::FromDer(Cow::Borrowed(SERVER_CERTIFICATE.cert.der()))
            .apply_to_connector(&mut ssl, crate::host::Host::Domain(SERVER_HOSTNAME))
            .expect("can configure TLS");

        let transport = TcpStream::connect(addr).await.expect("can connect");

        #[derive(Debug)]
        struct DelegateToInnerUnlessFlagSet {
            inner: TcpStream,
            flag: Arc<AtomicBool>,
        }

        impl tokio::io::AsyncRead for DelegateToInnerUnlessFlagSet {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }

        impl tokio::io::AsyncWrite for DelegateToInnerUnlessFlagSet {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, std::io::Error>> {
                if self.flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return Poll::Ready(Ok(1000));
                }
                Pin::new(&mut self.inner).poll_write(cx, buf)
            }

            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Result<(), std::io::Error>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }

            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Result<(), std::io::Error>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                bufs: &[std::io::IoSlice<'_>],
            ) -> Poll<Result<usize, std::io::Error>> {
                if self.flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return Poll::Ready(Ok(1000));
                }
                Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
            }

            fn is_write_vectored(&self) -> bool {
                self.inner.is_write_vectored()
            }
        }

        let flag = Arc::new(AtomicBool::new(false));

        let connection = tokio_boring_signal::connect(
            ssl.build().configure().expect("valid"),
            SERVER_HOSTNAME,
            WorkaroundWriteBugDuplexStream::new(DelegateToInnerUnlessFlagSet {
                inner: transport,
                flag: flag.clone(),
            }),
        )
        .await
        .expect("successful handshake");

        flag.store(true, std::sync::atomic::Ordering::Relaxed);
        let err = make_http_request_response_over(connection)
            .await
            .expect_err("should have been detected");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        assert!(err.to_string().contains("misbehaving write()"));
    }
}
