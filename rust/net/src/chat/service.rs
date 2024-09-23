//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use libsignal_net_infra::connection_manager::{ConnectionManager, ErrorClassifier};
use libsignal_net_infra::errors::LogSafeDisplay;
use libsignal_net_infra::service::{RemoteAddressInfo, Service, ServiceConnector};
use tokio::time::Instant;

use crate::chat::{
    ChatService, ChatServiceError, ChatServiceWithDebugInfo, DebugInfo, IpType, Request, Response,
};

#[async_trait]
impl<C, M> ChatService for Service<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector + Send + Sync + 'static,
    C::Service: ChatService + Clone + Sync + Send + 'static,
    C::Channel: Send + Sync,
    C::ConnectError:
        Send + Sync + Debug + LogSafeDisplay + ErrorClassifier + Into<ChatServiceError>,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError> {
        self.service().await?.send(msg, timeout).await
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        Ok(self.connect().await?)
    }

    async fn disconnect(&self) {
        self.disconnect().await;
    }
}

#[async_trait]
impl<C, M> ChatServiceWithDebugInfo for Service<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector + Send + Sync + 'static,
    C::Service: ChatService + RemoteAddressInfo + Clone + Sync + Send + 'static,
    C::Channel: Send + Sync,
    C::ConnectError:
        Send + Sync + Debug + LogSafeDisplay + ErrorClassifier + Into<ChatServiceError>,
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
                let method_for_log = msg.method.clone();
                let path_for_log_without_query = msg.path.path().to_owned();

                let result = s.send(msg, deadline - Instant::now()).await;

                if let Err(e) = &result {
                    // This is likely partially redundant with whatever logs the caller might do,
                    // but it ensures the connection info is included.
                    log::warn!(
                        "[{} {}] failed to complete request: {} ({})",
                        method_for_log,
                        path_for_log_without_query,
                        e,
                        s.connection_info().description()
                    );
                }

                (
                    result,
                    IpType::from_host(&s.connection_info().address),
                    s.connection_info().description(),
                )
            }
            Err(e) => (Err(e.into()), IpType::Unknown, "".to_string()),
        };
        let duration = start.elapsed();
        (
            response,
            DebugInfo {
                ip_type,
                duration,
                connection_info,
            },
        )
    }

    async fn connect_and_debug(&self) -> Result<DebugInfo, ChatServiceError> {
        let start = Instant::now();

        self.connect().await?;

        let connection_info = self.connection_info().await?;
        let ip_type = IpType::from_host(&connection_info.address);
        let connection_info = connection_info.description();
        let duration = start.elapsed();
        Ok(DebugInfo {
            ip_type,
            duration,
            connection_info,
        })
    }
}
