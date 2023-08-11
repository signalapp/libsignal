//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Error, Result};
use crate::QuicCallbackListener;
use ring::rand::*;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::panic::RefUnwindSafe;
use std::task::Poll;

const MAX_DATAGRAM_SIZE: usize = 1350;

enum Protocol {
    Pwave,
    Swave,
}

impl Protocol {
    fn value(&self) -> String {
        match self {
            Protocol::Pwave => "pwave".to_owned(),
            Protocol::Swave => "swave".to_owned(),
        }
    }

    fn fin(&self) -> bool {
        match self {
            Protocol::Pwave => false,
            Protocol::Swave => true,
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join("")
}

struct SwaveQuicCallbackListener {
    data: Vec<u8>
}

struct PwaveQuicCallbackListener<'r> {
    len: Vec<u8>,
    buf: Vec<u8>,
    wrapped: &'r mut dyn QuicCallbackListener,
}

impl QuicCallbackListener for SwaveQuicCallbackListener {
    fn on_data<'life0, 'async_trait>(
        &'life0 mut self,
        mut data: Vec<u8>,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<()>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.data.append(&mut data);
        Box::pin(async { Ok(()) })
    }
}

impl<'r> QuicCallbackListener for PwaveQuicCallbackListener<'r> {
    fn on_data<'life0, 'async_trait>(
        &'life0 mut self,
        mut data: Vec<u8>,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<()>> + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let remaining = 4 - self.len.len();
        if remaining > 0 {
            if remaining > data.len() {
                self.len.append(&mut data);
            } else {
                self.len.append(&mut data[..remaining].to_vec());
            }
        }

        if self.len.len() == 4 {
            let cloned_len = self.len.clone();
            let len: usize = u32::from_be_bytes(cloned_len.try_into().unwrap()).try_into().unwrap();

            if self.buf.len() < len {
                let remaining = len - self.buf.len();
                if remaining > data.len() {
                    self.buf.append(&mut data);
                } else {
                    self.buf.append(&mut data[..remaining].to_vec());
                }
            }

            if self.buf.len() == len {
                let cloned_buf = self.buf.clone();
                self.len = vec![];
                self.buf = vec![];
                self.wrapped.on_data(cloned_buf);
            }
        }

        Box::pin(async { Ok(()) })
    }
}

pub struct QuicClient {
    target: String,
    pub tokio_runtime: tokio::runtime::Runtime,
    sender: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    next_stream_id: u64,
}

impl RefUnwindSafe for QuicClient {}

impl QuicClient {
    pub fn new(target: String) -> Result<Self> {
        Ok(QuicClient {
            target,
            tokio_runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::InvalidArgument(format!("tokio.create_runtime: {:?}", e)))?,
            sender: None,
            next_stream_id: 0,
        })
    }

    pub fn target(&mut self, target: &str) {
        self.target = target.to_owned();
    }

    pub fn send_message(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        println!("Send quic message: data.len={}", data.len());
        let mut listener = SwaveQuicCallbackListener {
            data: vec![]
        };

        let stream_id = self.generate_stream_id(false);
        let target = self.target.clone();
        self.tokio_runtime.block_on(async {
            Self::async_send_message(stream_id, target, data, &mut listener).await
        });

        Ok(listener.data)
    }

    async fn async_send_message(stream_id: u64, target: String, data: &[u8], listener: &mut dyn QuicCallbackListener) {
        Self::send(target, Protocol::Swave, stream_id, data, None, listener).await
    }

    pub fn open_controlled_stream(
        &mut self,
        base_url: String,
        headers: HashMap<String, String>,
        listener: &mut dyn QuicCallbackListener,
    ) -> Result<()> {
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        self.sender = Some(sender);

        let mut pwave_listener = PwaveQuicCallbackListener {
            len: vec![],
            buf: vec![],
            wrapped: listener,
        };

        let stream_id = self.generate_stream_id(false);
        let target = self.target.clone();
        self.tokio_runtime.block_on(async {
            Self::async_open_controlled_stream(stream_id, target, base_url, headers, receiver, &mut pwave_listener).await
        })
    }

    async fn async_open_controlled_stream(
        stream_id: u64,
        target: String,
        base_url: String,
        headers: HashMap<String, String>,
        receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
        listener: &mut dyn QuicCallbackListener,
    ) -> Result<()> {
        let mut initial_data = vec![];
        let mut url_bytes = base_url.as_bytes().to_vec();
        let mut count_bytes = i32::try_from(url_bytes.len()).unwrap().to_be_bytes().to_vec();
        initial_data.append(&mut count_bytes);
        initial_data.append(&mut url_bytes);

        let mut headers_length_bytes = (headers.len()).to_be_bytes().to_vec();
        initial_data.append(&mut headers_length_bytes);
        for (header_key, header_val) in headers.iter() {
            let header_key_bytes = header_key.as_bytes();
            let header_val_bytes = header_val.as_bytes();
            initial_data.append(&mut header_key_bytes.len().to_be_bytes().to_vec());
            initial_data.append(&mut header_key_bytes.to_vec());
            initial_data.append(&mut header_val_bytes.len().to_be_bytes().to_vec());
            initial_data.append(&mut header_val_bytes.to_vec());
        }

        Self::send(target, Protocol::Pwave, stream_id, &initial_data, Some(receiver), listener).await;

        Ok(())
    }

    pub fn write_message_on_stream(&mut self, payload: &[u8]) -> Result<()> {
        println!(
            "Sending quic message on stream: payload.len={}",
            payload.len()
        );
        self.tokio_runtime
            .block_on(async { self.async_write_message_on_stream(payload).await })
    }

    async fn async_write_message_on_stream(&self, payload: &[u8]) -> Result<()> {
        if let Some(sender) = self.sender.as_ref() {
            sender
                .send(payload.to_vec())
                .await
                .map_err(|e| Error::InvalidArgument(format!("{:?}", e)))
        } else {
            Err(Error::StreamNotOpened())
        }
    }

    async fn send(target: String, proto: Protocol, stream_id: u64, data: &[u8], mut receiver: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>, listener: &mut dyn QuicCallbackListener) {
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        let final_target = format!("{}://{}", proto.value(), target);
        println!("Connecting to: {}", final_target);
        let url = url::Url::parse(&final_target).unwrap();

        // Setup the event loop.
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        // Resolve server address.
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();

        // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
        // server address. This is needed on macOS and BSD variants that don't
        // support binding to IN6ADDR_ANY for both v4 and v6.
        let bind_addr = match peer_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        // Create the UDP socket backing the QUIC connection, and register it with
        // the event loop.
        let mut socket =
            mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();

        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        // *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);

        config
            .set_application_protos(&[
                proto.value().as_bytes(),
            ])
            .unwrap();

        config.set_max_idle_timeout(120000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Get local address.
        let local_addr = socket.local_addr().unwrap();

        // Create a QUIC connection and initiate handshake.
        let mut conn =
            quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config)
                .unwrap();

        println!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let (write, send_info) = conn.send(&mut out).expect("initial send failed");

        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                println!("send() would block");
                continue;
            }

            panic!("send() failed: {:?}", e);
        }

        println!("written {}", write);

        let req_start = std::time::Instant::now();

        let mut req_sent = false;

        loop {
            poll.poll(&mut events, conn.timeout()).unwrap();

            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                // If the event loop reported no events, it means that the timeout
                // has expired, so handle it without attempting to read packets. We
                // will then proceed with the send loop.
                if events.is_empty() {
                    println!("timed out");

                    conn.on_timeout();
                    break 'read;
                }

                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("recv() would block");
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    },
                };

                println!("got {} bytes", len);

                let recv_info = quiche::RecvInfo {
                    to: socket.local_addr().unwrap(),
                    from,
                };

                // Process potentially coalesced packets.
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        eprintln!("recv failed: {:?}", e);
                        continue 'read;
                    },
                };

                println!("processed {} bytes", read);
            }

            println!("done reading");

            if conn.is_closed() {
                println!("connection closed, {:?}", conn.stats());
                break;
            }

            // Send an HTTP request as soon as the connection is established.
            if conn.is_established() {
                if !req_sent {
                    println!("sending initial request");

                    conn.stream_send(stream_id, &data, proto.fin())
                        .unwrap();

                    req_sent = true;
                } else if let Some(receiver) = receiver.as_mut() {
                    let waker = futures::task::noop_waker();
                    let mut cx = std::task::Context::from_waker(&waker);

                    match receiver.poll_recv(&mut cx) {
                        Poll::Ready(Some(d)) => conn.stream_send(stream_id, &d, false),
                        _ => Ok(0),
                    }.unwrap();
                }
            }

            // Process all readable streams.
            for s in conn.readable() {
                while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                    println!("received {} bytes", read);

                    let stream_buf = &buf[..read];

                    println!(
                        "stream {} has {} bytes (fin? {})",
                        s,
                        stream_buf.len(),
                        fin
                    );

                    println!("Response: {}", hex_dump(stream_buf));

                    // The server reported that it has no more data to send, which
                    // we got the full response. Close the connection.
                    if s == stream_id && fin {
                        println!(
                            "response received in {:?}, closing...",
                            req_start.elapsed()
                        );

                        conn.close(true, 0x00, b"kthxbye").unwrap();
                    }

                    listener.on_data(stream_buf.to_vec()).await.unwrap();
                }
            }

            // Generate outgoing QUIC packets and send them on the UDP socket, until
            // quiche reports that there are no more packets to be sent.
            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        println!("done writing");
                        break;
                    },

                    Err(e) => {
                        eprintln!("send failed: {:?}", e);

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        println!("send() would block");
                        break;
                    }

                    eprintln!("send() failed: {:?}", e);
                }

                println!("written {}", write);
            }

            if conn.is_closed() {
                println!("connection closed, {:?}", conn.stats());
                break;
            }
        }
    }

    fn generate_stream_id(&mut self, uni: bool) -> u64 {
        let mut stream_id = self.next_stream_id << 2;
        if uni {
            stream_id += 2;
        }
        self.next_stream_id = self.next_stream_id + 1;
        stream_id
    }
}
