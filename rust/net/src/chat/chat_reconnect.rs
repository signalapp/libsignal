//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use async_trait::async_trait;

use crate::chat::errors::ChatNetworkError;
use crate::chat::{ChatService, MessageProto, ResponseProto};
use crate::infra::reconnect::ServiceWithReconnect;

#[async_trait]
impl<T> ChatService for ServiceWithReconnect<T>
where
    T: ChatService + Clone + Sync + Send + 'static,
{
    async fn send(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        let service = self.service_clone().await;
        match service {
            Some(mut s) => s.send(msg, timeout).await,
            None => Err(ChatNetworkError::NoServiceConnection),
        }
    }
}
