//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod error;
pub use error::*;

mod request;
pub use request::*;

mod service;
pub use service::*;

mod session_id;
pub use session_id::*;

impl RegistrationService {
    pub async fn submit_captcha(
        &mut self,
        captcha_value: &str,
    ) -> Result<(), RequestError<UpdateSessionError>> {
        self.submit_request(UpdateRegistrationSession {
            captcha: Some(captcha_value),
            ..Default::default()
        })
        .await
        .map_err(Into::into)
    }

    pub async fn request_push_challenge(
        &mut self,
        push_token: &str,
        push_token_type: PushTokenType,
    ) -> Result<(), RequestError<UpdateSessionError>> {
        self.submit_request(UpdateRegistrationSession {
            push_token: Some(push_token),
            push_token_type: Some(push_token_type),
            ..Default::default()
        })
        .await
        .map_err(Into::into)
    }

    pub async fn request_verification_code(
        &mut self,
        transport: VerificationTransport,
        client: String,
    ) -> Result<(), RequestError<RequestVerificationCodeError>> {
        self.submit_request(RequestVerificationCode { transport, client })
            .await
            .map_err(Into::into)
    }

    pub async fn submit_push_challenge(
        &mut self,
        push_challenge: String,
    ) -> Result<(), RequestError<UpdateSessionError>> {
        self.submit_request(UpdateRegistrationSession {
            push_challenge: Some(push_challenge),
            ..Default::default()
        })
        .await
        .map_err(Into::into)
    }

    pub async fn submit_verification_code(
        &mut self,
        code: String,
    ) -> Result<(), RequestError<SubmitVerificationError>> {
        self.submit_request(SubmitVerificationCode { code })
            .await
            .map_err(Into::into)
    }
}

impl From<RequestError<SessionRequestError>> for RequestError<UpdateSessionError> {
    fn from(value: RequestError<SessionRequestError>) -> Self {
        value.map_other(|session_request_error| match session_request_error {
            SessionRequestError::RetryLater(retry_later) => RequestError::Other(retry_later.into()),
            SessionRequestError::UnrecognizedStatus { status, .. } => match status.as_u16() {
                403 => RequestError::Other(UpdateSessionError::Rejected),
                code => {
                    log::error!("got unexpected HTTP response status updating the session: {code}");
                    RequestError::Unknown(format!("unexpected HTTP status {code}"))
                }
            },
        })
    }
}

#[cfg(test)]
mod testutil {
    use std::convert::Infallible;
    use std::future::Future;
    use std::marker::PhantomData;

    use futures_util::future::BoxFuture;
    use futures_util::FutureExt as _;
    use tokio::sync::{mpsc, oneshot};

    use crate::chat::fake::FakeChatRemote;
    use crate::chat::ws2::ListenerEvent;
    use crate::chat::{ChatConnection, ConnectError as ChatConnectError};
    use crate::registration::ConnectChat;

    /// Fake [`ConnectChat`] impl that writes the remote end to a channel.
    pub(super) struct FakeChatConnect {
        pub(super) remote: mpsc::UnboundedSender<FakeChatRemote>,
    }

    pub(super) struct DropOnDisconnect<T>(Option<T>);

    impl<T> DropOnDisconnect<T> {
        pub(super) fn new(value: T) -> Self {
            Self(Some(value))
        }

        pub(super) fn into_listener(mut self) -> crate::chat::ws2::EventListener
        where
            T: Send + 'static,
        {
            Box::new(move |event| match event {
                ListenerEvent::ReceivedAlerts(alerts) => {
                    if !alerts.is_empty() {
                        unreachable!("unexpected alerts: {alerts:?}")
                    }
                }
                ListenerEvent::ReceivedMessage(_, _) => unreachable!("no incoming messages"),
                ListenerEvent::Finished(_reason) => drop(self.0.take()),
            })
        }
    }

    impl ConnectChat for FakeChatConnect {
        fn connect_chat(
            &self,
            on_disconnect: oneshot::Sender<Infallible>,
        ) -> BoxFuture<'_, Result<ChatConnection, ChatConnectError>> {
            let (fake_chat, fake_remote) = ChatConnection::new_fake(
                tokio::runtime::Handle::current(),
                DropOnDisconnect::new(on_disconnect).into_listener(),
                [],
            );
            async {
                let _ignore_failure = self.remote.send(fake_remote);
                Ok(fake_chat)
            }
            .boxed()
        }
    }

    /// [`ConnectChat`] impl that wraps a [`Fn`].
    pub(super) struct ConnectChatFn<'a, F>(F, PhantomData<&'a ()>);

    impl<F> ConnectChatFn<'_, F> {
        pub(super) fn new(f: F) -> Self {
            Self(f, PhantomData)
        }
    }

    impl<'a, F, Fut> ConnectChat for ConnectChatFn<'a, F>
    where
        F: Fn(oneshot::Sender<Infallible>) -> Fut + Send,
        Fut: Future<Output = Result<ChatConnection, ChatConnectError>> + Send + 'a,
    {
        fn connect_chat(
            &self,
            on_disconnect: oneshot::Sender<Infallible>,
        ) -> BoxFuture<'_, Result<ChatConnection, ChatConnectError>> {
            self.0(on_disconnect).boxed()
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr as _;

    use assert_matches::assert_matches;
    use tokio::sync::mpsc;

    use super::*;
    use crate::proto::chat_websocket::WebSocketRequestMessage;
    use crate::registration::testutil::FakeChatConnect;

    #[tokio::test]
    async fn create_session() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnect {
            remote: fake_chat_remote_tx,
        };

        let create_session = RegistrationService::create_session(
            CreateSession {
                number: "+18005550101".to_owned(),
                ..Default::default()
            },
            Box::new(fake_connect),
        );

        const SESSION_ID: &str = "sessionId";
        let make_session = || RegistrationSession {
            allowed_to_request_code: true,
            verified: false,
            ..Default::default()
        };

        tokio::spawn(async move {
            let fake_chat_remote = fake_chat_remote_rx.recv().await.expect("started connect");

            let incoming_request = fake_chat_remote
                .receive_request()
                .await
                .expect("still receiving")
                .expect("received request");

            assert_eq!(
                incoming_request,
                WebSocketRequestMessage {
                    verb: Some("POST".to_string()),
                    path: Some("/v1/verification/session".to_string()),
                    body: Some(b"{\"number\":\"+18005550101\"}".into()),
                    headers: vec!["content-type: application/json".to_string()],
                    id: Some(0),
                }
            );

            fake_chat_remote
                .send_response(
                    RegistrationResponse {
                        session_id: SESSION_ID.to_owned(),
                        session: make_session(),
                    }
                    .into_websocket_response(incoming_request.id()),
                )
                .expect("sent");
        });

        let service = create_session.await.expect("can create session");

        assert_eq!(**service.session_id(), SESSION_ID);
        assert_eq!(service.session_state(), &make_session())
    }

    #[tokio::test]
    async fn resume_session() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnect {
            remote: fake_chat_remote_tx,
        };
        const SESSION_ID: &str = "abcabc";

        let resume_session = RegistrationService::resume_session(
            SessionId::from_str(SESSION_ID).unwrap(),
            Box::new(fake_connect),
        );

        tokio::spawn(async move {
            let fake_chat_remote = fake_chat_remote_rx.recv().await.expect("sender not closed");
            let incoming_request = fake_chat_remote
                .receive_request()
                .await
                .expect("still receiving")
                .expect("received request");

            assert_eq!(
                incoming_request,
                WebSocketRequestMessage {
                    verb: Some("GET".to_string()),
                    path: Some("/v1/verification/session/abcabc".to_string()),
                    body: None,
                    headers: vec![],
                    id: Some(0),
                }
            );

            fake_chat_remote
                .send_response(
                    RegistrationResponse {
                        session_id: SESSION_ID.to_owned(),
                        session: RegistrationSession {
                            allowed_to_request_code: true,
                            verified: false,
                            ..Default::default()
                        },
                    }
                    .into_websocket_response(0),
                )
                .expect("not disconnected");
            fake_chat_remote
        });

        let session_client = resume_session.await;

        // At this point the client should be connected and can make additional
        // requests.
        let session_client = session_client.expect("resumed session");
        assert_eq!(
            session_client.session_id(),
            &SessionId::from_str(SESSION_ID).unwrap()
        );
    }

    #[tokio::test]
    async fn resume_session_and_make_requests() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnect {
            remote: fake_chat_remote_tx,
        };
        const SESSION_ID: &str = "abcabc";

        let resume_session = RegistrationService::resume_session(
            SessionId::from_str(SESSION_ID).unwrap(),
            Box::new(fake_connect),
        );

        let answer_resume_request = async {
            let fake_chat_remote = fake_chat_remote_rx.recv().await.expect("sender not closed");
            let incoming_request = fake_chat_remote
                .receive_request()
                .await
                .expect("still receiving")
                .expect("received request");

            assert_eq!(
                incoming_request,
                WebSocketRequestMessage {
                    verb: Some("GET".to_string()),
                    path: Some("/v1/verification/session/abcabc".to_string()),
                    body: None,
                    headers: vec![],
                    id: Some(0),
                }
            );

            fake_chat_remote
                .send_response(
                    RegistrationResponse {
                        session_id: SESSION_ID.to_owned(),
                        session: RegistrationSession {
                            allowed_to_request_code: true,
                            verified: false,
                            ..Default::default()
                        },
                    }
                    .into_websocket_response(0),
                )
                .expect("not disconnected");
            fake_chat_remote
        };

        let (session_client, fake_chat_remote) =
            tokio::join!(resume_session, answer_resume_request);

        // At this point the client should be connected and can make additional
        // requests.
        let mut session_client = session_client.expect("resumed session");

        let submit_captcha = session_client.submit_captcha("captcha value");

        let answer_submit_captcha = async move {
            let incoming_request = fake_chat_remote
                .receive_request()
                .await
                .expect("still receiving")
                .expect("received request");

            assert_eq!(
                incoming_request,
                WebSocketRequestMessage {
                    verb: Some("PATCH".to_string()),
                    path: Some("/v1/verification/session/abcabc".to_string()),
                    body: Some(b"{\"captcha\":\"captcha value\"}".into()),
                    headers: vec!["content-type: application/json".to_owned()],
                    id: Some(1),
                }
            );

            fake_chat_remote
                .send_response(
                    RegistrationResponse {
                        session_id: SESSION_ID.to_owned(),
                        session: RegistrationSession {
                            allowed_to_request_code: true,
                            verified: true,
                            ..Default::default()
                        },
                    }
                    .into_websocket_response(1),
                )
                .expect("not disconnected");
            fake_chat_remote
        };

        let (submit_result, _fake_chat_remote) =
            tokio::join!(submit_captcha, answer_submit_captcha);
        assert_matches!(submit_result, Ok(()));
    }
}
