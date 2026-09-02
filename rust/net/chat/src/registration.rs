//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::num::NonZeroU16;
use std::panic::UnwindSafe;

use libsignal_core::Aci;
use libsignal_net::chat::{LanguageList, Request as ChatRequest, Response as ChatResponse};
use libsignal_protocol::{KeyPair, PublicKey};
use static_assertions::assert_impl_all;
use zkgroup::receipts::ReceiptCredentialPresentation;

use crate::api::Registration;
use crate::api::registration::*;

mod service;
pub use service::*;

pub type RequestError<T> = crate::api::RequestError<T, Infallible>;

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

/// Refreshes `cached` from a request result before propagating it.
///
/// On success the cache is set to the response's session; on a failure that
/// carries server session state (see [`WithRecoveredSession`]) the cache is
/// updated from the recovered session before the error is returned, so
/// [`RegistrationService::session_state`] always reflects the latest
/// server-reported state.
fn update_session<E>(
    cached: &mut RegistrationSession,
    outcome: Result<RegistrationResponse, WithRecoveredSession<RequestError<E>>>,
) -> Result<(), RequestError<E>> {
    match outcome {
        Ok(RegistrationResponse { session, .. }) => {
            *cached = session;
            Ok(())
        }
        Err(WithRecoveredSession {
            result: err,
            session: recovered_session,
        }) => {
            if let Some(session) = recovered_session {
                log::debug!("refreshing cached session state from error response");
                *cached = session;
            }
            Err(err)
        }
    }
}

impl<'c> RegistrationService<'c> {
    /// Creates a new registration session with the server.
    ///
    /// Yields a [`RegistrationService`] when the server responds successfully,
    /// or an error if the request failed. This method will retry internally if
    /// transient errors are encountered.
    pub async fn create_session(
        create_session: CreateSession,
        connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + 'c>,
    ) -> Result<Self, RequestError<CreateSessionError>> {
        log::info!("starting new registration session");
        let connection = RegistrationConnection::connect(connect_chat).await?;
        let response = Registration(&connection)
            .create_session(&create_session)
            .await?;
        let RegistrationResponse {
            session_id,
            session,
        } = response;
        let number = create_session.number;

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
        connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + 'c>,
    ) -> Result<Self, RequestError<ResumeSessionError>> {
        log::info!("trying to resume existing registration session with session ID {session_id}");
        let connection = RegistrationConnection::connect(connect_chat).await?;
        let response = Registration(&connection).get_session(&session_id).await?;

        let RegistrationResponse {
            session_id: _,
            session,
        } = response;
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
        let Self {
            session_id,
            connection,
            session,
            number: _,
        } = self;
        log::info!("sending submit captcha on registration session {session_id}");

        let RegistrationResponse {
            session_id: _,
            session: response_session,
        } = Registration(&*connection)
            .submit_captcha(session_id, captcha_value)
            .await?;

        log::info!("submit captcha succeeded");
        *session = response_session;
        Ok(())
    }

    pub async fn request_push_challenge(
        &mut self,
        push_token: &PushToken,
    ) -> Result<(), RequestError<UpdateSessionError>> {
        let Self {
            session_id,
            connection,
            session,
            number: _,
        } = self;
        log::info!("sending request push challenge on registration session {session_id}");

        let RegistrationResponse {
            session_id: _,
            session: response_session,
        } = Registration(&*connection)
            .request_push_challenge(session_id, push_token)
            .await?;

        log::info!("request push challenge succeeded");
        *session = response_session;
        Ok(())
    }

    pub async fn request_verification_code(
        &mut self,
        transport: VerificationTransport,
        client: &str,
        languages: LanguageList,
    ) -> Result<(), RequestError<RequestVerificationCodeError>> {
        let Self {
            session_id,
            connection,
            session,
            number: _,
        } = self;
        log::info!("sending request verification code on registration session {session_id}");

        let outcome = Registration(&*connection)
            .request_verification_code(session_id, transport, client, languages)
            .await;

        if outcome.is_ok() {
            log::info!("request verification code succeeded");
        }
        update_session(session, outcome)
    }

    pub async fn submit_push_challenge(
        &mut self,
        push_challenge: &str,
    ) -> Result<(), RequestError<UpdateSessionError>> {
        let Self {
            session_id,
            connection,
            session,
            number: _,
        } = self;
        log::info!("sending submit push challenge on registration session {session_id}");

        let RegistrationResponse {
            session_id: _,
            session: response_session,
        } = Registration(&*connection)
            .submit_push_challenge(session_id, push_challenge)
            .await?;

        log::info!("submit push challenge succeeded");
        *session = response_session;
        Ok(())
    }

    pub async fn submit_verification_code(
        &mut self,
        code: &str,
    ) -> Result<(), RequestError<SubmitVerificationError>> {
        let Self {
            session_id,
            connection,
            session,
            number: _,
        } = self;
        log::info!("sending submit verification code on registration session {session_id}");

        let outcome = Registration(&*connection)
            .submit_verification_code(session_id, code)
            .await;

        if outcome.is_ok() {
            log::info!("submit verification code succeeded");
        }
        update_session(session, outcome)
    }

    pub async fn check_svr2_credentials(
        &mut self,
        svr_tokens: &[String],
    ) -> Result<CheckSvr2CredentialsResponse, RequestError<CheckSvr2CredentialsError>> {
        let Self {
            number, connection, ..
        } = self;
        log::info!("sending unauthenticated check SVR2 credentials request");

        let response = Registration(&*connection)
            .check_svr2_credentials(number, svr_tokens)
            .await?;

        log::info!("unauthenticated SVR2 credentials check succeeded");

        Ok(response)
    }

    pub async fn register_account(
        &mut self,
        message_notification: NewMessageNotification<&str>,
        account_attributes: ProvidedAccountAttributes<'_>,
        device_transfer: Option<SkipDeviceTransfer>,
        aci_keys: AccountKeys<'_>,
        pni_material: PniAccountMaterial<'_>,
        account_password: &str,
    ) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
        let Self {
            connection,
            session_id,
            number,
            session: _,
        } = self;

        log::info!("sending register account request");

        let response = Registration(&*connection)
            .register_account(
                RegisterAccountMethod::SessionId { number, session_id },
                message_notification,
                account_attributes,
                device_transfer,
                // Only offered for accounts with no phone number.
                None,
                aci_keys,
                Some(pni_material),
                account_password,
            )
            .await?;
        log::info!("register account succeeded");

        Ok(response)
    }
}

pub async fn reregister_account(
    number: &str,
    connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + '_>,
    message_notification: NewMessageNotification<&str>,
    account_attributes: ProvidedAccountAttributes<'_>,
    device_transfer: Option<SkipDeviceTransfer>,
    aci_keys: AccountKeys<'_>,
    pni_material: PniAccountMaterial<'_>,
    account_password: &str,
) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
    log::info!("sending re-register account request");

    let response = connect_and_register_account(
        connect_chat,
        RegisterAccountMethod::PhoneNumberRecoveryPassword { number },
        message_notification,
        account_attributes,
        device_transfer,
        // Only offered for accounts with no phone number.
        None,
        aci_keys,
        Some(pni_material),
        account_password,
    )
    .await?;

    log::info!("reregister account request succeeded");
    Ok(response)
}

/// Registers a new account that has no phone number.
///
/// `account_attributes.recovery_password` MUST NOT be empty. The phone number
/// flows accept an empty one, but an account with no phone number can only ever
/// be recovered by its recovery password. An empty one is reported as
/// [`RegisterAccountError::RecoveryPasswordRequired`] without sending anything.
pub async fn register_account_without_number(
    receipt_credential_presentation: &ReceiptCredentialPresentation,
    connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + '_>,
    message_notification: NewMessageNotification<&str>,
    account_attributes: ProvidedAccountAttributes<'_>,
    device_transfer: Option<SkipDeviceTransfer>,
    aci_keys: AccountKeys<'_>,
    account_password: &str,
) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
    log::info!("sending register account without number request");

    let response = connect_and_register_account(
        connect_chat,
        RegisterAccountMethod::ReceiptCredential {
            presentation: receipt_credential_presentation,
        },
        message_notification,
        account_attributes,
        device_transfer,
        // This flow only ever creates a brand-new account, so there is
        // nothing to check a code against.
        None,
        aci_keys,
        None,
        account_password,
    )
    .await?;

    log::info!("register account without number request succeeded");
    Ok(response)
}

/// Re-registers the account with the given ACI.
///
/// Like [`reregister_account`], but identifying the account by its ACI rather
/// than a phone number.
///
/// `rng` is used to generate a temporary valid PNI key material for the request.
/// It should be valid to pass any validation, but will be discarded by the server.
#[expect(clippy::too_many_arguments)]
pub async fn reregister_account_without_number(
    aci: Aci,
    connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + '_>,
    message_notification: NewMessageNotification<&str>,
    account_attributes: ProvidedAccountAttributes<'_>,
    device_transfer: Option<SkipDeviceTransfer>,
    one_time_password: Option<u32>,
    aci_keys: AccountKeys<'_>,
    account_password: &str,
    mut rng: &mut (dyn rand::CryptoRng + Send),
) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
    log::info!("sending re-register account without number request");

    let pni = FakePniKeys::generate(&mut rng);

    let response = connect_and_register_account(
        connect_chat,
        RegisterAccountMethod::AccountRecoveryPassword { aci },
        message_notification,
        account_attributes,
        device_transfer,
        one_time_password,
        aci_keys,
        Some(pni.as_material()),
        account_password,
    )
    .await?;

    log::info!("reregister account without number request succeeded");
    Ok(response)
}

/// PNI key material generated only to satisfy the server validation. Never actually used.
struct FakePniKeys {
    registration_id: NonZeroU16,
    identity_key: PublicKey,
    signed_pre_key: SignedPreKeyBody<Box<[u8]>>,
    pq_last_resort_pre_key: SignedPreKeyBody<Box<[u8]>>,
}

/// Upper bound for pre-key ID.
///
/// Matches the bound clients use.
const MAX_PRE_KEY_ID: u32 = 0xFF_FFFF;

/// Upper bound for registration ID.
///
/// Matches Java's `KeyHelper.generateRegistrationId`.
const MAX_REGISTRATION_ID: u16 = 16380;

impl FakePniKeys {
    fn generate<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let identity = KeyPair::generate(&mut *rng);

        let signed_pre_key = {
            let public_key = KeyPair::generate(&mut *rng).public_key.serialize();
            let signature = identity
                .private_key
                .calculate_signature(&public_key, &mut *rng)
                .expect("can sign");
            SignedPreKeyBody {
                key_id: rng.random_range(0..MAX_PRE_KEY_ID),
                public_key,
                signature,
            }
        };
        let pq_last_resort_pre_key = {
            let public_key = libsignal_protocol::kem::KeyPair::generate(
                libsignal_protocol::kem::KeyType::Kyber1024,
                &mut *rng,
            )
            .public_key
            .serialize();
            let signature = identity
                .private_key
                .calculate_signature(&public_key, &mut *rng)
                .expect("can sign");
            SignedPreKeyBody {
                key_id: rng.random_range(0..MAX_PRE_KEY_ID),
                public_key,
                signature,
            }
        };

        Self {
            registration_id: NonZeroU16::new(rng.random_range(1..=MAX_REGISTRATION_ID))
                .expect("valid range"),
            identity_key: identity.public_key,
            signed_pre_key,
            pq_last_resort_pre_key,
        }
    }

    fn as_material(&self) -> PniAccountMaterial<'_> {
        PniAccountMaterial {
            registration_id: self.registration_id.get(),
            keys: AccountKeys {
                identity_key: &self.identity_key,
                signed_pre_key: self.signed_pre_key.as_deref(),
                pq_last_resort_pre_key: self.pq_last_resort_pre_key.as_deref(),
            },
        }
    }
}

#[expect(clippy::too_many_arguments)]
async fn connect_and_register_account(
    connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + '_>,
    method: RegisterAccountMethod<'_>,
    message_notification: NewMessageNotification<&str>,
    account_attributes: ProvidedAccountAttributes<'_>,
    device_transfer: Option<SkipDeviceTransfer>,
    one_time_password: Option<u32>,
    aci_keys: AccountKeys<'_>,
    pni_material: Option<PniAccountMaterial<'_>>,
    account_password: &str,
) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
    if method.requires_recovery_password() && account_attributes.recovery_password.is_empty() {
        return Err(RequestError::Other(
            RegisterAccountError::RecoveryPasswordRequired,
        ));
    }

    let connection = RegistrationConnection::connect(connect_chat).await?;
    let response = Registration(&connection)
        .register_account(
            method,
            message_notification,
            account_attributes,
            device_transfer,
            one_time_password,
            aci_keys,
            pni_material,
            account_password,
        )
        .await?;
    Ok(response)
}

#[cfg(test)]
mod testutil {
    use std::convert::Infallible;
    use std::future::Future;
    use std::marker::PhantomData;

    use futures_util::FutureExt as _;
    use futures_util::future::BoxFuture;
    use libsignal_net::chat::fake::FakeChatRemote;
    use libsignal_net::chat::ws::ListenerEvent;
    use libsignal_net::chat::{ChatConnection, ConnectError as ChatConnectError};
    use tokio::sync::{mpsc, oneshot};

    use crate::api::Unauth;
    use crate::registration::ConnectUnauthChat;

    /// Fake [`ConnectChat`] impl that writes the remote end to a channel.
    pub(super) struct FakeChatConnect {
        pub(super) remote: mpsc::UnboundedSender<FakeChatRemote>,
    }

    pub(super) struct DropOnDisconnect<T>(Option<T>);

    impl<T> DropOnDisconnect<T> {
        pub(super) fn new(value: T) -> Self {
            Self(Some(value))
        }

        pub(super) fn into_listener(mut self) -> libsignal_net::chat::ws::EventListener
        where
            T: Send + 'static,
        {
            Box::new(move |event| match event {
                ListenerEvent::ServerTimestamp(_) => {}
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

    impl ConnectUnauthChat for FakeChatConnect {
        fn connect_chat(
            &self,
            on_disconnect: oneshot::Sender<Infallible>,
        ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ChatConnectError>> {
            let (fake_chat, fake_remote) = ChatConnection::new_fake(
                tokio::runtime::Handle::current(),
                DropOnDisconnect::new(on_disconnect).into_listener(),
                [],
                [],
            );
            async {
                let _ignore_failure = self.remote.send(fake_remote);
                Ok(Unauth(fake_chat))
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

    impl<'a, F, Fut> ConnectUnauthChat for ConnectChatFn<'a, F>
    where
        F: Fn(oneshot::Sender<Infallible>) -> Fut + Send,
        Fut: Future<Output = Result<Unauth<ChatConnection>, ChatConnectError>> + Send + 'a,
    {
        fn connect_chat(
            &self,
            on_disconnect: oneshot::Sender<Infallible>,
        ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ChatConnectError>> {
            self.0(on_disconnect).boxed()
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use std::str::FromStr as _;

    use assert_matches::assert_matches;
    use bytes::Bytes;
    use futures_util::FutureExt as _;
    use futures_util::future::BoxFuture;
    use libsignal_net::chat::fake::FakeChatRemote;
    use libsignal_net::chat::{ChatConnection, ConnectError};
    use libsignal_net::proto::chat_websocket::WebSocketRequestMessage;
    use rand::TryRngCore as _;
    use rand::rngs::OsRng;
    use tokio::sync::mpsc;

    use super::*;
    use crate::api::Unauth;
    use crate::ws::registration::RegistrationResponse;

    // Mimics server verification. Not a real thing, but a static snapshot of one.
    #[test]
    fn fake_pni_keys_should_be_verifiable_by_server() {
        let mut rng = crate::api::testutil::fixed_seed_test_rng();
        let keys = FakePniKeys::generate(&mut rng);
        let material = keys.as_material();

        for pre_key in [
            material.keys.signed_pre_key,
            material.keys.pq_last_resort_pre_key,
        ] {
            assert!(
                material
                    .keys
                    .identity_key
                    .verify_signature(pre_key.public_key, pre_key.signature),
                "signature verification failed"
            );
            assert!(pre_key.key_id < MAX_PRE_KEY_ID, "{}", pre_key.key_id);
        }
        assert!(
            material.registration_id <= MAX_REGISTRATION_ID,
            "registration ID {} too large",
            material.registration_id
        );
    }

    #[test]
    fn fake_pni_keys_do_not_reuse_ids() {
        let mut rng = crate::api::testutil::fixed_seed_test_rng();
        let first = FakePniKeys::generate(&mut rng);
        let second = FakePniKeys::generate(&mut rng);

        assert_ne!(first.registration_id, second.registration_id);
        assert_ne!(first.signed_pre_key.key_id, second.signed_pre_key.key_id);
        assert_ne!(
            first.pq_last_resort_pre_key.key_id,
            second.pq_last_resort_pre_key.key_id
        );
    }

    struct ConnectMustNotBeCalled;

    impl ConnectUnauthChat for ConnectMustNotBeCalled {
        fn connect_chat(
            &self,
            _on_disconnect: tokio::sync::oneshot::Sender<std::convert::Infallible>,
        ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ConnectError>> {
            panic!("should not connect")
        }
    }

    #[tokio::test]
    async fn register_account_without_number_rejects_empty_recovery_password() {
        let mut rng = OsRng.unwrap_err();
        let identity_key = libsignal_protocol::KeyPair::generate(&mut rng).public_key;
        let pre_key = SignedPreKeyBody {
            key_id: 1,
            public_key: &b"public key"[..],
            signature: &b"signature"[..],
        };

        let result = register_account_without_number(
            &crate::api::testutil::valid_receipt_credential_presentation(),
            Box::new(ConnectMustNotBeCalled),
            NewMessageNotification::WillFetchMessages,
            ProvidedAccountAttributes {
                recovery_password: b"",
                registration_id: 123,
                name: None,
                registration_lock: None,
                unidentified_access_key: &[0; 16],
                unrestricted_unidentified_access: false,
                capabilities: HashSet::new(),
                discoverable_by_phone_number: false,
            },
            Some(SkipDeviceTransfer),
            AccountKeys {
                identity_key: &identity_key,
                signed_pre_key: pre_key,
                pq_last_resort_pre_key: pre_key,
            },
            "encoded account password",
        )
        .await;

        assert_matches!(
            result,
            Err(RequestError::Other(
                RegisterAccountError::RecoveryPasswordRequired
            ))
        );
    }

    struct ConnectOnlyOnce<C>(std::sync::Mutex<Option<C>>);

    impl<C: ConnectUnauthChat> ConnectUnauthChat for ConnectOnlyOnce<C> {
        fn connect_chat(
            &self,
            on_disconnect: tokio::sync::oneshot::Sender<std::convert::Infallible>,
        ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ConnectError>> {
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
                    body: Some(Bytes::from_static(b"{\"number\":\"+18005550101\"}")),
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
                    body: Some(Bytes::from_static(b"{\"captcha\":\"captcha value\"}")),
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

    #[test_log::test(tokio::test(start_paused = true))]
    async fn session_state_is_cached_from_error_responses() {
        use std::time::Duration;

        use libsignal_net::proto::chat_websocket::WebSocketResponseMessage;

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
            fake_chat_remote
                .send_response(
                    RegistrationResponse {
                        session_id: SESSION_ID.to_owned(),
                        session: RegistrationSession::default(),
                    }
                    .into_websocket_response(incoming_request.id()),
                )
                .expect("not disconnected");
            fake_chat_remote
        };
        let (service, fake_chat_remote) = tokio::join!(resume_session, answer_resume_request);
        let mut service = service.expect("resumed session");
        assert_eq!(service.session_state(), &RegistrationSession::default());

        // Responds to the next request with `status` and a body carrying `session`.
        let answer_with_session =
            async |remote: FakeChatRemote, status: u16, session: &RegistrationSession| {
                let incoming_request = remote
                    .receive_request()
                    .await
                    .expect("still receiving")
                    .expect("received request");
                let mut headers = vec!["content-type: application/json".to_owned()];
                if status == 429 {
                    // 429 maps to `RetryLater` only when a retry-after header is present.
                    headers.push("retry-after: 60".to_owned());
                }
                remote
                    .send_response(WebSocketResponseMessage {
                        id: Some(incoming_request.id()),
                        status: Some(status.into()),
                        message: Some("error".to_string()),
                        headers,
                        body: Some(serde_json::to_vec(session).unwrap().into()),
                    })
                    .expect("not disconnected");
                remote
            };

        // A failed `request_verification_code` whose body carries updated session
        // state refreshes the cache even though the call returns an error.
        let failed_session = RegistrationSession {
            allowed_to_request_code: false,
            next_sms: Some(Duration::from_secs(42)),
            ..Default::default()
        };
        let request_code = service.request_verification_code(
            VerificationTransport::Sms,
            "libsignal test",
            LanguageList::default(),
        );
        let (result, fake_chat_remote) = tokio::join!(
            request_code,
            answer_with_session(fake_chat_remote, 418, &failed_session)
        );
        assert_matches!(
            result,
            Err(RequestError::Other(
                RequestVerificationCodeError::SendFailed(Some(_))
            ))
        );
        assert_eq!(service.session_state(), &failed_session);

        // Likewise for `submit_verification_code` failing with NotReadyForVerification.
        let failed_session = RegistrationSession {
            next_verification_attempt: Some(Duration::from_secs(37)),
            ..Default::default()
        };
        let submit_code = service.submit_verification_code("123456");
        let (result, fake_chat_remote) = tokio::join!(
            submit_code,
            answer_with_session(fake_chat_remote, 409, &failed_session)
        );
        assert_matches!(
            result,
            Err(RequestError::Other(
                SubmitVerificationError::NotReadyForVerification(Some(_))
            ))
        );
        assert_eq!(service.session_state(), &failed_session);

        // A 429 carries the session in its body too, but (unlike 409/418) surfaces
        // as the generic `RetryLater` error. The cache is still refreshed from the
        // session recovered out-of-band.
        let rate_limited_session = RegistrationSession {
            next_sms: Some(Duration::from_secs(99)),
            ..Default::default()
        };
        let request_code = service.request_verification_code(
            VerificationTransport::Sms,
            "libsignal test",
            LanguageList::default(),
        );
        let (result, fake_chat_remote) = tokio::join!(
            request_code,
            answer_with_session(fake_chat_remote, 429, &rate_limited_session)
        );
        assert_matches!(result, Err(RequestError::RetryLater(_)));
        assert_eq!(service.session_state(), &rate_limited_session);

        // Same for `submit_verification_code`.
        let rate_limited_session = RegistrationSession {
            next_verification_attempt: Some(Duration::from_secs(11)),
            ..Default::default()
        };
        let submit_code = service.submit_verification_code("123456");
        let (result, fake_chat_remote) = tokio::join!(
            submit_code,
            answer_with_session(fake_chat_remote, 429, &rate_limited_session)
        );
        assert_matches!(result, Err(RequestError::RetryLater(_)));
        assert_eq!(service.session_state(), &rate_limited_session);

        drop(fake_chat_remote);
    }
}
