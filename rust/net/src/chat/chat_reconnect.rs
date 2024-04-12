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
        self.service().await?.send(msg, timeout).await
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        Ok(self.connect_from_inactive().await?)
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
        let start = Instant::now();
        let deadline = start + timeout;
        let service = self.service().await;
        let (response, ip_type, connection_info) = match service {
            Ok(s) => {
                let result = s.send(msg, deadline - Instant::now()).await;
                (
                    result,
                    IpType::from_host(&s.connection_info().address),
                    s.connection_info().description(),
                )
            }
            Err(e) => (Err(e.into()), IpType::Unknown, "".to_string()),
        };
        let duration = start.elapsed();
        let reconnect_count = self.reconnect_count();
        (
            response,
            DebugInfo {
                reconnect_count,
                ip_type,
                duration,
                connection_info,
            },
        )
    }

    async fn connect_and_debug(&self) -> Result<DebugInfo, ChatServiceError> {
        let start = Instant::now();

        self.connect_from_inactive().await?;

        let connection_info = self.connection_info().await?;
        let ip_type = IpType::from_host(&connection_info.address);
        let connection_info = connection_info.description();
        let duration = start.elapsed();
        let reconnect_count = self.reconnect_count();
        Ok(DebugInfo {
            reconnect_count,
            ip_type,
            duration,
            connection_info,
        })
    }
}
