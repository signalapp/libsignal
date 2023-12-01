//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;

use crate::chat::{ChatService, Request, ResponseProto};
use crate::infra::connection_manager::ConnectionManager;
use crate::infra::errors::{LogSafeDisplay, NetError};
use crate::infra::reconnect::{ServiceConnector, ServiceWithReconnect};

#[async_trait]
impl<C, M> ChatService for ServiceWithReconnect<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector + Send + Sync + 'static,
    C::Service: ChatService + Clone + Sync + Send + 'static,
    C::Channel: Send + Sync,
    C::Error: Send + Sync + Debug + LogSafeDisplay,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<ResponseProto, NetError> {
        let service = self.service_clone().await;
        match service {
            Some(s) => s.send(msg, timeout).await,
            None => Err(NetError::NoServiceConnection),
        }
    }
}
