//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use prost::Message;

use crate::error::{Error, Result};
use crate::proto::signal::profile::{profile_client, GetVersionedProfileRequest};
use std::panic::RefUnwindSafe;

pub struct ProfileClient {
    target: String,
    pub tokio_runtime: tokio::runtime::Runtime,
}

impl RefUnwindSafe for ProfileClient {}

impl ProfileClient {
    pub fn new(target: String) -> Result<Self> {
        Ok(ProfileClient {
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

    pub fn get_versioned_profile(&self, request: &[u8]) -> Result<Vec<u8>> {
        self.tokio_runtime
            .block_on(async { self.async_get_versioned_profile(request).await })
    }

    async fn async_get_versioned_profile(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut profile_client = profile_client::ProfileClient::connect(self.target.clone())
            .await
            .map_err(|e| Error::InvalidArgument(format!("profile_client.connect: {:?}", e)))?;

        let request: GetVersionedProfileRequest = Message::decode(&request[..])
            .map_err(|e| Error::InvalidArgument(format!("profile_client.decode: {:?}", e)))?;

        let response = profile_client
            .get_versioned_profile(request)
            .await
            .map_err(|e| Error::InvalidArgument(format!("get_versioned_profile: {:?}", e)))?;

        let response = response.into_inner();
        Ok(response.encode_to_vec())
    }
}
