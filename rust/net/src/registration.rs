//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::panic::UnwindSafe;

use libsignal_net_infra::route::Captures;
use static_assertions::assert_impl_all;

mod error;
pub use error::*;

mod request;
pub use request::*;

mod service;
pub use service::*;

mod session_id;
pub use session_id::*;

/// A client for the Signal registration API endpoints.
///
/// A client is tied to a single registration session (identified by the session
/// ID). It manages a semi-persistent connection to the Chat service that is
/// used to communicate with Signal servers.
#[derive(Debug)]
pub struct RegistrationService<'c> {
    session: RegistrationSession,
    connection: RegistrationConnection<'c>,
    session_id: SessionId,
    number: String,
}

assert_impl_all!(RegistrationService<'static>: UnwindSafe);

impl<'c> RegistrationService<'c> {
    /// Creates a new registration session with the server.
    ///
    /// Yields a [`RegistrationService`] when the server responds successfully,
    /// or an error if the request failed. This method will retry internally if
    /// transient errors are encountered.
    pub async fn create_session(
        create_session: CreateSession,
        connect_chat: Box<dyn ConnectChat + Send + Sync + UnwindSafe + 'c>,
    ) -> Result<Self, RequestError<CreateSessionError>> {
        log::info!("starting new registration session");
        let number = create_session.number.clone();

        let (connection, response) =
            RegistrationConnection::connect_and_send(connect_chat, create_session.into()).await?;

        let RegistrationResponse {
            session_id,
            session,
        } = response.try_into_response()?;

        let session_id = session_id.parse()?;
        log::info!("started registration session with session ID {session_id}");

        Ok(Self {
            session_id,
            number,
            connection,
            session,
        })
    }

    /// Resumes a previous registration session with the server.
    ///
    /// Yields a [`RegistrationService`] when the server responds successfully,
    /// or an error if the request failed. This method will retry internally if
    /// transient errors are encountered.
    pub async fn resume_session(
        session_id: SessionId,
        number: String,
        connect_chat: Box<dyn ConnectChat + Send + Sync + UnwindSafe + 'c>,
    ) -> Result<Self, RequestError<ResumeSessionError>> {
        log::info!("trying to resume existing registration session with session ID {session_id}");
        let (connection, response) = RegistrationConnection::connect_and_send(
            connect_chat,
            RegistrationRequest {
                session_id: &session_id,
                request: GetSession {},
            }
            .into(),
        )
        .await?;

        let RegistrationResponse {
            session_id: _,
            session,
        } = response.try_into_response()?;
        log::info!("successfully resumed registration session");

        Ok(Self {
            session_id,
            connection,
            session,
            number,
        })
    }

    /// Returns the server identifier for the bound session.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the last known server-reported state of the session.
    pub fn session_state(&self) -> &RegistrationSession {
        &self.session
    }

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
        client: &str,
        languages: &[String],
    ) -> Result<(), RequestError<RequestVerificationCodeError>> {
        let language_list = (!languages.is_empty())
            .then(|| languages.join(", ").parse())
            .transpose()
            .map_err(|_| {
                RequestError::<RequestVerificationCodeError>::Unknown(
                    "invalid language list".to_owned(),
                )
            })?;
        self.submit_request(RequestVerificationCode {
            transport,
            client,
            language_list: language_list.as_ref().map(LanguageList),
        })
        .await
        .map_err(Into::into)
    }

    pub async fn submit_push_challenge(
        &mut self,
        push_challenge: &str,
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
        code: &str,
    ) -> Result<(), RequestError<SubmitVerificationError>> {
        self.submit_request(SubmitVerificationCode { code })
            .await
            .map_err(Into::into)
    }

    pub async fn check_svr2_credentials(
        &mut self,
        svr_tokens: &[String],
    ) -> Result<CheckSvr2CredentialsResponse, RequestError<CheckSvr2CredentialsError>> {
        let Self {
            number, connection, ..
        } = self;
        log::info!("sending unauthenticated check SVR2 credentials request");

        let response = connection
            .submit_chat_request(
                CheckSvr2CredentialsRequest {
                    number,
                    tokens: svr_tokens,
                }
                .into(),
            )
            .await?;

        log::info!("unauthenticated SVR2 credentials check succeeded");

        response
            .try_into_response()
            .map_err(|e| RequestError::<SessionRequestError>::from(e).into())
    }

    pub async fn register_account(
        &mut self,
        message_notification: NewMessageNotification<&str>,
        account_attributes: ProvidedAccountAttributes<'_>,
        device_transfer: Option<SkipDeviceTransfer>,
        keys: ForServiceIds<AccountKeys<'_>>,
        account_password: &[u8],
    ) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
        let Self {
            connection,
            session_id,
            number,
            session: _,
        } = self;

        let request = crate::chat::Request::register_account(
            number,
            Some(session_id),
            message_notification,
            account_attributes,
            device_transfer,
            keys,
            account_password,
        );

        log::info!("sending register account request");
        let response = connection.submit_chat_request(request).await?;
        log::info!("register account succeeded");

        response
            .try_into_response()
            .map_err(|e| RequestError::<SessionRequestError>::from(e).into())
    }

    /// Sends a request for an established session.
    ///
    /// On success, the state of the session as reported by the server is saved
    /// (and accessible via [`Self::session_state`]). This method will retry
    /// internally if transient errors are encountered.
    fn submit_request<R: Request>(
        &mut self,
        request: R,
        // Write this as `impl Future` so we can include the `Send` bound, which
        // lets us surface errors earlier.
    ) -> impl Future<Output = Result<(), RequestError<SessionRequestError>>>
           + Send
           + Captures<&'_ ()>
           + Captures<&'c ()> {
        // Delegate to a non-templated function to reduce code size cost.
        async fn submit_request_impl(
            this: &mut RegistrationService<'_>,
            request: crate::chat::Request,
            request_type: &'static str,
        ) -> Result<(), RequestError<SessionRequestError>> {
            let RegistrationService {
                connection,
                session,
                session_id,
                number: _,
            } = this;
            log::info!("sending {request_type} on registration session {session_id}");

            let response = connection.submit_chat_request(request).await?;

            log::info!("{request_type} succeeded");
            let RegistrationResponse {
                session_id: _,
                session: response_session,
            } = response.try_into_response()?;

            *session = response_session;
            Ok(())
        }

        submit_request_impl(
            self,
            RegistrationRequest {
                request,
                session_id: &self.session_id,
            }
            .into(),
            std::any::type_name::<R>(),
        )
    }
}

pub async fn reregister_account(
    number: &str,
    connect_chat: Box<dyn ConnectChat + Send + Sync + UnwindSafe + '_>,
    message_notification: NewMessageNotification<&str>,
    account_attributes: ProvidedAccountAttributes<'_>,
    device_transfer: Option<SkipDeviceTransfer>,
    keys: ForServiceIds<AccountKeys<'_>>,
    account_password: &[u8],
) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
    let request = crate::chat::Request::register_account(
        number,
        None,
        message_notification,
        account_attributes,
        device_transfer,
        keys,
        account_password,
    );

    log::info!("sending regregister account request");

    let (_connection, response) =
        RegistrationConnection::connect_and_send(connect_chat, request).await?;

    log::info!("reregister account request succeded");
    response
        .try_into_response()
        .map_err(|e| RequestError::<SessionRequestError>::from(e).into())
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
    use futures_util::future::BoxFuture;
    use futures_util::FutureExt as _;
    use tokio::sync::mpsc;

    use super::*;
    use crate::chat::fake::FakeChatRemote;
    use crate::chat::{ChatConnection, ConnectError};
    use crate::proto::chat_websocket::WebSocketRequestMessage;

    struct ConnectOnlyOnce<C>(std::sync::Mutex<Option<C>>);

    impl<C: ConnectChat> ConnectChat for ConnectOnlyOnce<C> {
        fn connect_chat(
            &self,
            on_disconnect: tokio::sync::oneshot::Sender<std::convert::Infallible>,
        ) -> BoxFuture<'_, Result<ChatConnection, ConnectError>> {
            let inner = self
                .0
                .lock()
                .expect("not locked")
                .take()
                .expect("only one connect is allowed");

            async move { inner.connect_chat(on_disconnect).await }.boxed()
        }
    }

    type FakeChatConnectOnce = ConnectOnlyOnce<crate::registration::testutil::FakeChatConnect>;

    impl FakeChatConnectOnce {
        fn new(remote_tx: mpsc::UnboundedSender<FakeChatRemote>) -> Self {
            Self(Some(crate::registration::testutil::FakeChatConnect { remote: remote_tx }).into())
        }
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn create_session() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnectOnce::new(fake_chat_remote_tx);

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

        let remote_respond = async move {
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
            fake_chat_remote
        };

        let (service, fake_chat_remote) = tokio::join!(create_session, remote_respond);

        let service = service.expect("can create session");

        assert_eq!(**service.session_id(), SESSION_ID);
        assert_eq!(service.session_state(), &make_session());
        // If the remote end goes away too early the client complains.
        drop(fake_chat_remote);
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn resume_session() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnectOnce::new(fake_chat_remote_tx);
        const SESSION_ID: &str = "abcabc";

        let resume_session = RegistrationService::resume_session(
            SessionId::from_str(SESSION_ID).unwrap(),
            "+18005550101".to_string(),
            Box::new(fake_connect),
        );

        let remote_respond = async {
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
            // Yield the remote instead of dropping it so the fake server
            // doesn't disconnect.
            fake_chat_remote
        };

        let (session_client, fake_chat_remote) = tokio::join!(resume_session, remote_respond);

        // At this point the client should be connected and can make additional
        // requests.
        let session_client = session_client.expect("resumed session");
        assert_eq!(
            session_client.session_id(),
            &SessionId::from_str(SESSION_ID).unwrap()
        );
        // If the remote end goes away too early the client complains.
        drop(fake_chat_remote);
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn resume_session_and_make_requests() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnectOnce::new(fake_chat_remote_tx);
        const SESSION_ID: &str = "abcabc";

        let resume_session = RegistrationService::resume_session(
            SessionId::from_str(SESSION_ID).unwrap(),
            "+18005550101".to_string(),
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

        let answer_submit_captcha = async {
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
        };

        let (submit_result, ()) = tokio::join!(submit_captcha, answer_submit_captcha);
        assert_matches!(submit_result, Ok(()));
        // If the remote end goes away too early the client complains.
        drop(fake_chat_remote);
    }
}
