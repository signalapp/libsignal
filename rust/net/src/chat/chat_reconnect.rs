//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::Instant;

use crate::chat::{
    ChatService, ChatServiceError, ChatServiceWithDebugInfo, DebugInfo, IpType, RemoteAddressInfo,
    Request, Response,
};
use crate::infra::connection_manager::ConnectionManager;
use crate::infra::errors::LogSafeDisplay;
use crate::infra::reconnect::{ServiceConnector, ServiceWithReconnect};

#[async_trait]
impl<C, M> ChatService for ServiceWithReconnect<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector + Send + Sync + 'static,
    C::Service: ChatService + Clone + Sync + Send + 'static,
    C::Channel: Send + Sync,
    C::ConnectError: Send + Sync + Debug + LogSafeDisplay,
    C::StartError: Send + Sync + Debug + LogSafeDisplay,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError> {
        let service = self.service_clone().await;
        match service {
            Some(s) => s.send(msg, timeout).await,
            None => Err(ChatServiceError::NoServiceConnection),
        }
    }

    async fn disconnect(&self) {
        self.disconnect().await;
    }
}

#[async_trait]
impl<C, M> ChatServiceWithDebugInfo for ServiceWithReconnect<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector + Send + Sync + 'static,
    C::Service: ChatService + RemoteAddressInfo + Clone + Sync + Send + 'static,
    C::Channel: Send + Sync,
    C::ConnectError: Send + Sync + Debug + LogSafeDisplay,
    C::StartError: Send + Sync + Debug + LogSafeDisplay,
{
    async fn send_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo) {
        let deadline = Instant::now() + timeout;
        let is_connected = self.is_connected(deadline).await;
        let service = self.service_clone().await;
        let (response, ip_type) = match service {
            Some(s) => {
                let result = s.send(msg, deadline - Instant::now()).await;
                (result, s.remote_address().into())
            }
            None => (Err(ChatServiceError::NoServiceConnection), IpType::Unknown),
        };
        (
            response,
            DebugInfo {
                reconnect_count: self.reconnect_count(),
                connection_reused: is_connected,
                ip_type,
            },
        )
    }
}
