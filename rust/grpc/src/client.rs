//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{error::{Error, Result}, proto};
use std::collections::HashMap;

pub struct GrpcClient {
    tokio_runtime: tokio::runtime::Runtime,
}

impl GrpcClient {
    pub fn new() -> Result<Self> {
        Ok(GrpcClient {
            tokio_runtime: tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .map_err(|e| Error::InvalidArgument(format!("tokio.create_runtime: {:?}", e)))?
        })
    }

    pub fn send_message(&self, method: String, url_fragment: String, body: &[u8], headers: HashMap<String, Vec<String>>) -> Result<Vec<u8>> {
        println!("Tunneling gRPC message: method={} url_fragment={}, body.len={}, headers={:?}", method, url_fragment, body.len(), headers);
        self.tokio_runtime.block_on(async {
            self.tunnel_message(method, url_fragment, body, headers).await
        })
    }

    async fn tunnel_message(&self, method: String, url_fragment: String, body: &[u8], headers: HashMap<String, Vec<String>>) -> Result<Vec<u8>> {
        let mut tunnel = proto::proxy::tunnel_client::TunnelClient::connect("https://grpcproxy.gluonhq.net:443").await
            .map_err(|e| Error::InvalidArgument(format!("tunnel.connect: {:?}", e)))?;

        let mut request_headers = vec![];
        for (header_name, header_values) in headers.iter() {
            for header_value in header_values.iter() {
                request_headers.push(format!("{}={}", header_name, header_value))
            }
        }

        let request = proto::proxy::SignalRpcMessage {
            body: body.to_vec(),
            method,
            urlfragment: url_fragment,
            header: request_headers,
        };

        let response = tunnel.send_some_message(request).await
            .map_err(|e| Error::InvalidArgument(format!("tunnel.send_some_message: {:?}", e)))?;

        Ok(response.get_ref().message.as_bytes().to_vec())
    }
}
