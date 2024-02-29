//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use prost::Message;

use crate::error::{Error, Result};
use crate::proto::signal::device::{devices_client, GetDevicesRequest};
use std::panic::RefUnwindSafe;

pub struct DeviceClient {
    target: String,
    pub tokio_runtime: tokio::runtime::Runtime,
}

impl RefUnwindSafe for DeviceClient {}

impl DeviceClient {
    pub fn new(target: String) -> Result<Self> {
        Ok(DeviceClient {
            target,
            tokio_runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| Error::InvalidArgument(format!("tokio.create_runtime: {:?}", e)))?,
        })
    }

    pub fn target(&mut self, target: &str) {
        self.target = target.to_owned();
    }

    pub fn get_devices(&self, request: &[u8], authorization: String) -> Result<Vec<u8>> {
        self.tokio_runtime
            .block_on(async { self.async_get_devices(request, authorization).await })
    }

    async fn async_get_devices(&self, request: &[u8], authorization: String) -> Result<Vec<u8>> {
        let channel = tonic::transport::Channel::from_shared(self.target.clone())
            .map_err(|e| Error::InvalidArgument(format!("devices_client.connect: {:?}", e)))?
            .connect()
            .await
            .map_err(|e| Error::InvalidArgument(format!("devices_client.connect: {:?}", e)))?;

        let mut devices_client = devices_client::DevicesClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut()
                .insert("authorization", tonic::metadata::MetadataValue::try_from(&authorization).unwrap());
            Ok(req)
        });

        let request: GetDevicesRequest = Message::decode(&request[..])
            .map_err(|e| Error::InvalidArgument(format!("devices_client.decode: {:?}", e)))?;

        let response = devices_client
            .get_devices(request)
            .await
            .map_err(|e| Error::InvalidArgument(format!("devices_client.get_devices: {:?}", e)))?;

        let response = response.into_inner();
        Ok(response.encode_to_vec())
    }
}
