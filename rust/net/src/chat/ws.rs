//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::status::StatusCode;
use libsignal_net_infra::ws::WebSocketClientWriter;
use libsignal_net_infra::AsyncDuplexStream;
use prost::Message;

use crate::chat::{ChatServiceError, MessageProto, ResponseProto};
use crate::proto::chat_websocket::web_socket_message::Type;

#[derive(Debug)]
pub struct ResponseSender<S> {
    request_id: u64,
    // Declared with Option for testing ServerRequest handlers.
    writer: Option<WebSocketClientWriter<S, ChatServiceError>>,
}

impl<S: AsyncDuplexStream> ResponseSender<S> {
    pub async fn send_response(self, status_code: StatusCode) -> Result<(), ChatServiceError> {
        let Some(writer) = self.writer else {
            return Ok(());
        };
        let response = response_for_code(self.request_id, status_code);
        writer.send(response.encode_to_vec()).await
    }
}

pub(super) fn response_for_code(id: u64, code: StatusCode) -> MessageProto {
    MessageProto {
        r#type: Some(Type::Response.into()),
        response: Some(ResponseProto {
            id: Some(id),
            status: Some(code.as_u16().into()),
            message: Some(
                code.canonical_reason()
                    .expect("has canonical reason")
                    .to_string(),
            ),
            headers: vec![],
            body: None,
        }),
        request: None,
    }
}
