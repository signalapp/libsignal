//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use libsignal_bridge_macros::*;
use libsignal_bridge_types::net::registration::{
    ConnectChatBridge, RegistrationCreateSessionRequest, RegistrationService,
};
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_net::auth::Auth;
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::ChatConnection;
use libsignal_net::infra::errors::RetryLater;
use libsignal_net::registration::{
    CheckSvr2CredentialsError, CheckSvr2CredentialsResponse, ConnectChat, CreateSessionError,
    RegisterAccountError, RegisterAccountResponse, RegisterResponseBackup, RegisterResponseBadge,
    RegisterResponseEntitlements, RegistrationLock, RegistrationSession, RequestError,
    RequestVerificationCodeError, RequestedInformation, ResumeSessionError,
    SubmitVerificationError, Svr2CredentialsResult, UpdateSessionError,
    VerificationCodeNotDeliverable,
};
use uuid::uuid;

use super::make_error_testing_enum;
use crate::net::chat::FakeChatServer;
use crate::*;

#[bridge_fn]
pub fn TESTING_RegistrationSessionInfoConvert() -> RegistrationSession {
    RegistrationSession {
        allowed_to_request_code: true,
        verified: true,
        next_call: Some(Duration::from_secs(123)),
        next_sms: Some(Duration::from_secs(456)),
        next_verification_attempt: Some(Duration::from_secs(789)),
        requested_information: HashSet::from([RequestedInformation::PushChallenge]),
    }
}

#[bridge_fn]
pub fn TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert(
) -> CheckSvr2CredentialsResponse {
    CheckSvr2CredentialsResponse {
        matches: [
            ("username:pass-match", Svr2CredentialsResult::Match),
            ("username:pass-no-match", Svr2CredentialsResult::NoMatch),
            ("username:pass-invalid", Svr2CredentialsResult::Invalid),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect(),
    }
}

#[derive(Clone)]
struct ConnectFakeChat(
    tokio::runtime::Handle,
    tokio::sync::mpsc::UnboundedSender<FakeChatRemote>,
);

struct ConnectFakeChatBridge(tokio::sync::mpsc::UnboundedSender<FakeChatRemote>);

impl ConnectChatBridge for ConnectFakeChatBridge {
    fn create_chat_connector(
        self: Box<Self>,
        runtime: tokio::runtime::Handle,
    ) -> Box<dyn ConnectChat + Send + Sync + std::panic::UnwindSafe> {
        let Self(tx) = *self;
        Box::new(ConnectFakeChat(runtime, tx))
    }
}
impl ConnectChat for ConnectFakeChat {
    fn connect_chat(
        &self,
        on_disconnect: tokio::sync::oneshot::Sender<std::convert::Infallible>,
    ) -> BoxFuture<'_, Result<ChatConnection, libsignal_net::chat::ConnectError>> {
        let mut on_disconnect = Some(on_disconnect);
        let listener = move |event| match event {
            libsignal_net::chat::ws2::ListenerEvent::Finished(_) => drop(on_disconnect.take()),
            libsignal_net::chat::ws2::ListenerEvent::ReceivedAlerts(_)
            | libsignal_net::chat::ws2::ListenerEvent::ReceivedMessage(_, _) => (),
        };

        let (chat, remote) = ChatConnection::new_fake(self.0.clone(), Box::new(listener), []);

        std::future::ready(
            self.1
                .send(remote)
                .map_err(|_| libsignal_net::chat::ConnectError::AllAttemptsFailed)
                .map(|()| chat),
        )
        .boxed()
    }
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FakeRegistrationSession_CreateSession(
    create_session: RegistrationCreateSessionRequest,
    chat: &FakeChatServer,
) -> Result<RegistrationService, RequestError<CreateSessionError>> {
    RegistrationService::create_session(
        Box::new(ConnectFakeChatBridge(chat.tx.clone())),
        tokio::runtime::Handle::current(),
        create_session,
    )
    .await
}

#[bridge_fn]
fn TESTING_RegisterAccountResponse_CreateTestValue() -> RegisterAccountResponse {
    RegisterAccountResponse {
        aci: uuid!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").into(),
        number: "+18005550123".to_owned(),
        pni: uuid!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").into(),
        username_hash: Some((*b"username-hash").into()),
        username_link_handle: Some(uuid!("55555555-5555-5555-5555-555555555555")),
        storage_capable: true,
        entitlements: RegisterResponseEntitlements {
            badges: [
                RegisterResponseBadge {
                    id: "first".to_owned(),
                    visible: true,
                    expiration: Duration::from_secs(123456),
                },
                RegisterResponseBadge {
                    id: "second".to_owned(),
                    visible: false,
                    expiration: Duration::from_secs(555),
                },
            ]
            .into(),
            backup: Some(RegisterResponseBackup {
                backup_level: 123,
                expiration: Duration::from_secs(888888),
            }),
        },
        reregistration: true,
    }
}

// Use aliases so that places that refer to syntactic argument names (e.g.
// jni::jni_arg and friends) aren't ambiguous.
/// cbindgen:ignore
type TestingCreateSessionRequestError = TestingRequestError<TestingCreateSessionError>;
/// cbindgen:ignore
type TestingResumeSessionRequestError = TestingRequestError<TestingResumeSessionError>;
/// cbindgen:ignore
type TestingUpdateSessionRequestError = TestingRequestError<TestingUpdateSessionError>;
/// cbindgen:ignore
type TestingRequestVerificationCodeRequestError =
    TestingRequestError<TestingRequestVerificationCodeError>;
/// cbindgen:ignore
type TestingSubmitVerificationRequestError = TestingRequestError<TestingSubmitVerificationError>;
/// cbindgen:ignore
type TestingRegisterAccountRequestError = TestingRequestError<TestingRegisterAccountError>;
/// cbindgen:ignore
type TestingCheckSvr2CredentialsRequestError =
    TestingRequestError<TestingCheckSvr2CredentialsError>;

struct TestingRequestError<E>(RequestError<E>);

impl<TestE> TestingRequestError<TestE> {
    fn map_into_error<E>(self, f: impl FnOnce(TestE) -> E) -> RequestError<E> {
        let TestingRequestError(inner) = self;
        match inner {
            RequestError::Timeout => RequestError::Timeout,
            RequestError::RequestWasNotValid => RequestError::RequestWasNotValid,
            RequestError::Unknown(message) => RequestError::Unknown(message),
            RequestError::Other(e) => RequestError::Other(f(e)),
        }
    }
}

const RETRY_AFTER_42_SECONDS: RetryLater = RetryLater {
    retry_after_seconds: 42,
};

impl<TestE: for<'a> TryFrom<&'a str, Error = strum::ParseError>> TryFrom<String>
    for TestingRequestError<TestE>
{
    type Error = strum::ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        RequestError::from_str(&value)
            .map(|e| match e {
                // Replace the always-empty message with one we can look for.
                RequestError::Unknown(message) => {
                    assert_eq!(message, "");
                    RequestError::Unknown("some message".to_string())
                }
                e => e,
            })
            .or_else(|_| TestE::try_from(&value).map(RequestError::Other))
            .map(Self)
    }
}

make_error_testing_enum!(
    enum TestingCreateSessionError for CreateSessionError {
        InvalidSessionId => InvalidSessionId,
        RetryLater => RetryAfter42Seconds,
    }
);

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_RegistrationService_CreateSessionErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingCreateSessionRequestError, String>,
) -> Result<(), RequestError<CreateSessionError>> {
    Err(error_description
        .into_inner()
        .map_into_error(|inner| match inner {
            TestingCreateSessionError::InvalidSessionId => CreateSessionError::InvalidSessionId,
            TestingCreateSessionError::RetryAfter42Seconds => {
                CreateSessionError::RetryLater(RETRY_AFTER_42_SECONDS)
            }
        }))
}

make_error_testing_enum!(
    enum TestingResumeSessionError for ResumeSessionError {
        InvalidSessionId => InvalidSessionId,
        SessionNotFound => SessionNotFound,
    }
);

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_RegistrationService_ResumeSessionErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingResumeSessionRequestError, String>,
) -> Result<(), RequestError<ResumeSessionError>> {
    Err(error_description
        .into_inner()
        .map_into_error(|inner| match inner {
            TestingResumeSessionError::InvalidSessionId => ResumeSessionError::InvalidSessionId,
            TestingResumeSessionError::SessionNotFound => ResumeSessionError::SessionNotFound,
        }))
}

make_error_testing_enum!(
    enum TestingUpdateSessionError for UpdateSessionError {
        Rejected => Rejected,
        RetryLater => RetryAfter42Seconds,
    }
);

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_RegistrationService_UpdateSessionErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingUpdateSessionRequestError, String>,
) -> Result<(), RequestError<UpdateSessionError>> {
    Err(error_description
        .into_inner()
        .map_into_error(|inner| match inner {
            TestingUpdateSessionError::Rejected => UpdateSessionError::Rejected,
            TestingUpdateSessionError::RetryAfter42Seconds => {
                UpdateSessionError::RetryLater(RETRY_AFTER_42_SECONDS)
            }
        }))
}

make_error_testing_enum!(
    enum TestingRequestVerificationCodeError for RequestVerificationCodeError {
        InvalidSessionId => InvalidSessionId,
        SessionNotFound => SessionNotFound,
        NotReadyForVerification => NotReadyForVerification,
        SendFailed => SendFailed,
        CodeNotDeliverable => CodeNotDeliverable,
        RetryLater => RetryAfter42Seconds,
    }
);

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_RegistrationService_RequestVerificationCodeErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingRequestVerificationCodeRequestError, String>,
) -> Result<(), RequestError<RequestVerificationCodeError>> {
    Err(error_description
        .into_inner()
        .map_into_error(|inner| match inner {
            TestingRequestVerificationCodeError::InvalidSessionId => {
                RequestVerificationCodeError::InvalidSessionId
            }
            TestingRequestVerificationCodeError::SessionNotFound => {
                RequestVerificationCodeError::SessionNotFound
            }
            TestingRequestVerificationCodeError::NotReadyForVerification => {
                RequestVerificationCodeError::NotReadyForVerification
            }
            TestingRequestVerificationCodeError::SendFailed => {
                RequestVerificationCodeError::SendFailed
            }
            TestingRequestVerificationCodeError::CodeNotDeliverable => {
                RequestVerificationCodeError::CodeNotDeliverable(VerificationCodeNotDeliverable {
                    reason: "no reason".to_owned(),
                    permanent_failure: true,
                })
            }
            TestingRequestVerificationCodeError::RetryAfter42Seconds => {
                RequestVerificationCodeError::RetryLater(RETRY_AFTER_42_SECONDS)
            }
        }))
}

make_error_testing_enum!(
    enum TestingSubmitVerificationError for SubmitVerificationError {
        InvalidSessionId => InvalidSessionId,
        SessionNotFound => SessionNotFound,
        NotReadyForVerification => NotReadyForVerification,
        RetryLater => RetryAfter42Seconds,
    }
);

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_RegistrationService_SubmitVerificationErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingSubmitVerificationRequestError, String>,
) -> Result<(), RequestError<SubmitVerificationError>> {
    Err(error_description
        .into_inner()
        .map_into_error(|inner| match inner {
            TestingSubmitVerificationError::InvalidSessionId => {
                SubmitVerificationError::InvalidSessionId
            }
            TestingSubmitVerificationError::SessionNotFound => {
                SubmitVerificationError::SessionNotFound
            }
            TestingSubmitVerificationError::NotReadyForVerification => {
                SubmitVerificationError::NotReadyForVerification
            }
            TestingSubmitVerificationError::RetryAfter42Seconds => {
                SubmitVerificationError::RetryLater(RETRY_AFTER_42_SECONDS)
            }
        }))
}

make_error_testing_enum!(
    enum TestingCheckSvr2CredentialsError for CheckSvr2CredentialsError {
        CredentialsCouldNotBeParsed => CredentialsCouldNotBeParsed,
    }
);

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingCheckSvr2CredentialsRequestError, String>,
) -> Result<(), RequestError<CheckSvr2CredentialsError>> {
    Err(error_description
        .into_inner()
        .map_into_error(|inner| match inner {
            TestingCheckSvr2CredentialsError::CredentialsCouldNotBeParsed => {
                CheckSvr2CredentialsError::CredentialsCouldNotBeParsed
            }
        }))
}

make_error_testing_enum!(
    enum TestingRegisterAccountError for RegisterAccountError {
        DeviceTransferIsPossibleButNotSkipped => DeviceTransferIsPossibleButNotSkipped,
        RegistrationRecoveryVerificationFailed => RegistrationRecoveryVerificationFailed,
        RegistrationLock => RegistrationLockFor50Seconds,
        RetryLater => RetryAfter42Seconds,
    }
);

/// Return an error matching the requested description.
#[bridge_fn(ffi = false)]
fn TESTING_RegistrationService_RegisterAccountErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingRegisterAccountRequestError, String>,
) -> Result<(), RequestError<RegisterAccountError>> {
    Err(error_description
        .into_inner()
        .map_into_error(|inner| match inner {
            TestingRegisterAccountError::RetryAfter42Seconds => {
                RegisterAccountError::RetryLater(RETRY_AFTER_42_SECONDS)
            }
            TestingRegisterAccountError::DeviceTransferIsPossibleButNotSkipped => {
                RegisterAccountError::DeviceTransferIsPossibleButNotSkipped
            }
            TestingRegisterAccountError::RegistrationRecoveryVerificationFailed => {
                RegisterAccountError::RegistrationRecoveryVerificationFailed
            }
            TestingRegisterAccountError::RegistrationLockFor50Seconds => {
                RegisterAccountError::RegistrationLock(RegistrationLock {
                    time_remaining: Duration::from_secs(50),
                    svr2_credentials: Auth {
                        username: "user".to_owned(),
                        password: "pass".to_owned(),
                    },
                })
            }
        }))
}
