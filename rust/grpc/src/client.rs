//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::{Error, Result};
use crate::{proto, GrpcReplyListener};
use std::collections::HashMap;
use std::panic::RefUnwindSafe;
use tokio_stream::StreamExt;

pub struct GrpcClient {
    target: String,
    pub tokio_runtime: tokio::runtime::Runtime,
    sender: Option<tokio::sync::mpsc::Sender<proto::proxy::SignalRpcMessage>>,
}

impl RefUnwindSafe for GrpcClient {}

#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct GrpcReply {
    pub statuscode: i32,
    pub message: Vec<u8>,
}

pub trait SignalRpcReplyListener: Send + Sync {
    fn on_reply(&self, reply: GrpcReply);
}

impl From<proto::proxy::SignalRpcReply> for GrpcReply {
    fn from(value: proto::proxy::SignalRpcReply) -> Self {
        GrpcReply {
            statuscode: value.statuscode,
            message: value.message,
        }
    }
}

impl From<&proto::proxy::SignalRpcReply> for GrpcReply {
    fn from(value: &proto::proxy::SignalRpcReply) -> Self {
        GrpcReply {
            statuscode: value.statuscode,
            message: value.message.clone(),
        }
    }
}

impl GrpcClient {
    pub fn new(target: String) -> Result<Self> {
        Ok(GrpcClient {
            target,
            tokio_runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| Error::InvalidArgument(format!("tokio.create_runtime: {:?}", e)))?,
            sender: None,
        })
    }

    pub fn target(&mut self, target: &str) {
        self.target = target.to_owned();
    }

    pub fn echo_message(&self, message: &str) -> Result<String> {
        println!("Received echo message: message={}", message);
        self.tokio_runtime
            .block_on(async { self.async_echo_message(message).await })
    }

    pub async fn async_echo_message(&self, message: &str) -> Result<String> {
        let mut tunnel = proto::proxy::tunnel_client::TunnelClient::connect(self.target.clone())
            .await
            .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?;

        let request = proto::proxy::EchoRequest {
            message: message.to_owned(),
        };

        let response = tunnel
            .echo_message(request)
            .await
            .map_err(|e| Error::InvalidArgument(format!("echo_message: {:?}", e)))?;

        Ok(response.get_ref().message.clone())
    }

    pub fn send_direct_message(
        &self,
        method: String,
        url_fragment: String,
        body: &[u8],
        headers: HashMap<String, Vec<String>>,
    ) -> Result<GrpcReply> {
        println!(
            "Tunneling gRPC message direct: method={} url_fragment={}, body.len={}, headers={:?}",
            method,
            url_fragment,
            body.len(),
            headers
        );
        self.tokio_runtime.block_on(async {
            self.async_send_direct_message(method, url_fragment, body, headers)
                .await
        })
    }

    async fn async_send_direct_message(
        &self,
        method: String,
        url_fragment: String,
        body: &[u8],
        headers: HashMap<String, Vec<String>>,
    ) -> Result<GrpcReply> {
        let mut tunnel = proto::proxy::tunnel_client::TunnelClient::connect(self.target.clone())
            .await
            .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?;

        let mut request_headers = vec![];
        for (header_name, header_values) in headers.iter() {
            for header_value in header_values.iter() {
                request_headers.push(format!("{}={}", header_name, header_value))
            }
        }

        let request = proto::proxy::SignalRpcMessage {
            method,
            urlfragment: url_fragment,
            body: body.to_vec(),
            header: request_headers,
        };

        let response = tunnel
            .send_some_message(request)
            .await
            .map_err(|e| Error::InvalidArgument(format!("send_message: {:?}", e)))?;

        Ok(response.get_ref().into())
    }

    pub fn open_stream(
        &mut self,
        uri: String,
        headers: HashMap<String, Vec<String>>,
        listener: &mut dyn GrpcReplyListener,
    ) -> Result<()> {
        let (sender, receiver) = tokio::sync::mpsc::channel(100);
        self.sender = Some(sender);

        let target = self.target.clone();
        self.tokio_runtime.block_on(async {
            Self::async_open_stream(target, uri, headers, receiver, listener).await
        })
    }

    async fn async_open_stream(
        target: String,
        uri: String,
        headers: HashMap<String, Vec<String>>,
        receiver: tokio::sync::mpsc::Receiver<proto::proxy::SignalRpcMessage>,
        listener: &mut dyn GrpcReplyListener,
    ) -> Result<()> {
        let channel = tonic::transport::Channel::from_shared(target)
            .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?
            .connect()
            .await
            .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?;

        let header_uri: tonic::metadata::MetadataValue<_> = uri
            .parse()
            .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?;
        let mut metadata_headers = HashMap::new();
        for (header_key, header_values) in headers.iter() {
            for header_value in header_values.iter() {
                let metadata_header_value: tonic::metadata::MetadataValue<_> = header_value
                    .parse()
                    .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?;
                let metadata_header_key: tonic::metadata::MetadataKey<_> = header_key
                    .parse()
                    .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?;
                metadata_headers.insert(
                    metadata_header_key.to_owned(),
                    metadata_header_value.to_owned(),
                );
            }
        }
        let headers: Vec<(
            tonic::metadata::MetadataKey<_>,
            tonic::metadata::MetadataValue<_>,
        )> = metadata_headers.into_iter().collect();

        let mut tunnel = proto::proxy::tunnel_client::TunnelClient::with_interceptor(
            channel,
            move |mut req: tonic::Request<()>| {
                let metadata = req.metadata_mut();
                metadata.append("uri", header_uri.clone());
                for (header_key, header_value) in headers.clone().into_iter() {
                    metadata.append(header_key.to_owned(), header_value.to_owned());
                }
                Ok(req)
            },
        );

        let receiver_stream = tokio_stream::wrappers::ReceiverStream::new(receiver);

        let mut response_stream = tunnel
            .stream_some_messages(receiver_stream)
            .await
            .map_err(|status| {
                Error::InvalidArgument(format!("tunnel.send_some_messages: status={}", status))
            })?
            .into_inner();
        while let Some(reply) = response_stream.next().await {
            match reply {
                Ok(reply) => listener.on_reply(reply.into()).await,
                Err(e) => listener.on_error(format!("{}", e)).await,
            }?
        }

        Ok(())
    }

    pub fn send_message_on_stream(
        &self,
        method: String,
        url_fragment: String,
        body: &[u8],
        headers: HashMap<String, Vec<String>>,
    ) -> Result<()> {
        println!("Tunneling gRPC message on stream: method={} url_fragment={}, body.len={}, headers={:?}", method, url_fragment, body.len(), headers);
        self.tokio_runtime.block_on(async {
            self.async_send_message_on_stream(method, url_fragment, body, headers)
                .await
        })
    }

    async fn async_send_message_on_stream(
        &self,
        method: String,
        url_fragment: String,
        body: &[u8],
        headers: HashMap<String, Vec<String>>,
    ) -> Result<()> {
        if let Some(sender) = self.sender.as_ref() {
            let mut request_headers = vec![];
            for (header_name, header_values) in headers.iter() {
                for header_value in header_values.iter() {
                    request_headers.push(format!("{}={}", header_name, header_value))
                }
            }

            sender
                .send(proto::proxy::SignalRpcMessage {
                    method,
                    urlfragment: url_fragment,
                    body: body.to_vec(),
                    header: request_headers,
                })
                .await
                .map_err(|e| Error::InvalidArgument(format!("{:?}", e)))
        } else {
            Err(Error::StreamNotOpened())
        }
    }
}
