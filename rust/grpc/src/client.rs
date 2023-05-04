//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{error::{Error, Result}, proto};

pub struct GrpcClient {
    tokio_runtime: tokio::runtime::Runtime,
}

impl GrpcClient {
    pub fn new() -> Result<Self> {
        Ok(GrpcClient {
            tokio_runtime: tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(|e| Error::InvalidArgument(format!("{}", e)))?
        })
    }

    pub fn send_message(&self, method: String, url_fragment: String, body: &[u8]) -> Result<Vec<u8>> {
        println!("Tunneling gRPC message: method={} url_fragment={}, body.len={}", method, url_fragment, body.len());
        self.tokio_runtime.block_on(async {
            self.tunnel_message(method, url_fragment, body).await
        })
    }

    async fn tunnel_message(&self, method: String, url_fragment: String, body: &[u8]) -> Result<Vec<u8>> {
        let mut tunnel = proto::proxy::tunnel_client::TunnelClient::connect("gluongrpcproxy.gluonhq.net:443").await
            .map_err(|e| Error::InvalidArgument(format!("{}", e)))?;

        let request = proto::proxy::SignalRpcMessage {
            body: body.to_vec(),
            method,
            urlfragment: url_fragment,
            header: vec![],
        };

        let response = tunnel.send_some_message(request).await
            .map_err(|e| Error::InvalidArgument(format!("{}", e)))?;

        Ok(response.get_ref().message.as_bytes().to_vec())
    }
}
