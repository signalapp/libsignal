//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::future::Future;

use http::{HeaderName, HeaderValue};
use libsignal_net::chat::{Request as ChatRequest, Response as ChatResponse};

use crate::api::registration::{
    AccountKeys, CheckSvr2CredentialsError, CheckSvr2CredentialsResponse, CreateSession,
    CreateSessionError, ForServiceIds, InvalidSessionId, NewMessageNotification,
    ProvidedAccountAttributes, PushTokenType, RegisterAccountError, RegisterAccountResponse,
    RegistrationChatApi, RegistrationResponse as RegistrationOutput, RequestVerificationCodeError,
    ResumeSessionError, SessionId, SkipDeviceTransfer, SubmitVerificationError, UpdateSessionError,
    VerificationTransport,
};
use crate::api::{Registration, RequestError};
use crate::ws::{ResponseError, TryIntoResponse, WsConnection, JSON_CONTENT_TYPE};

mod error;
mod request;

#[cfg(test)]
pub(crate) use request::RegistrationResponse;
use request::*;

/// A chat client that communicates with the server over a websocket.
///
/// This generalizes over implementations of [`WsConnection`] and
/// implementations that retry on certain errors internally.
pub(crate) trait WsClient {
    /// The type of an error returned by [`WsClient::send`].
    type SendError;

    fn send(
        &self,
        request: ChatRequest,
    ) -> impl Future<Output = Result<ChatResponse, Self::SendError>> + Send;
}

/// A type that can be infallibly converted into a [`RequestError<E, D>`] for
/// specific `D`.
pub(crate) trait SendError {
    /// The type of an error produced in response to being disconnected.
    type DisconnectError;

    fn into_request_error<E>(self) -> RequestError<E, Self::DisconnectError>;
}

/// `WsClient` generalizes [`WsConnection`], so every implementer of the latter
/// is also a valid implementation of the former.
impl<W: WsConnection> WsClient for W {
    type SendError = libsignal_net::chat::SendError;

    fn send(
        &self,
        request: ChatRequest,
    ) -> impl Future<Output = Result<ChatResponse, Self::SendError>> + Send {
        WsConnection::send(self, request)
    }
}

/// Map the websocket `SendError` using its `From` impl.
impl SendError for libsignal_net::chat::SendError {
    type DisconnectError = crate::api::DisconnectedError;

    fn into_request_error<E>(self) -> RequestError<E> {
        RequestError::from(self)
    }
}

impl<C: WsClient + Sync> RegistrationChatApi for Registration<C>
where
    C::SendError: SendError,
{
    type Error<E> = RequestError<E, <C::SendError as SendError>::DisconnectError>;

    async fn create_session(
        &self,
        create_session: &CreateSession,
    ) -> Result<RegistrationOutput, Self::Error<CreateSessionError>> {
        submit_request(&self.0, create_session).await
    }

    async fn get_session(
        &self,
        session_id: &SessionId,
    ) -> Result<RegistrationOutput, Self::Error<ResumeSessionError>> {
        submit_request(
            &self.0,
            RegistrationRequest {
                session_id,
                request: GetSession {},
            },
        )
        .await
    }

    async fn submit_captcha(
        &self,
        session_id: &SessionId,
        captcha_value: &str,
    ) -> Result<RegistrationOutput, Self::Error<UpdateSessionError>> {
        submit_request(
            &self.0,
            RegistrationRequest {
                session_id,
                request: UpdateRegistrationSession {
                    captcha: Some(captcha_value),
                    ..Default::default()
                },
            },
        )
        .await
    }

    async fn request_push_challenge(
        &self,
        session_id: &SessionId,
        push_token: &str,
        push_token_type: PushTokenType,
    ) -> Result<RegistrationOutput, Self::Error<UpdateSessionError>> {
        submit_request(
            &self.0,
            RegistrationRequest {
                session_id,
                request: UpdateRegistrationSession {
                    push_token: Some(push_token),
                    push_token_type: Some(push_token_type),
                    ..Default::default()
                },
            },
        )
        .await
    }

    async fn request_verification_code(
        &self,
        session_id: &SessionId,
        transport: VerificationTransport,
        client: &str,
        languages: &[String],
    ) -> Result<RegistrationOutput, Self::Error<RequestVerificationCodeError>> {
        let language_list = (!languages.is_empty())
            .then(|| languages.join(", ").parse())
            .transpose()
            .map_err(|_| RequestError::Unexpected {
                log_safe: "invalid language list".to_owned(),
            })?;
        submit_request(
            &self.0,
            RegistrationRequest {
                session_id,
                request: RequestVerificationCode {
                    transport,
                    client,
                    language_list: language_list.as_ref().map(LanguageList),
                },
            },
        )
        .await
    }

    async fn submit_push_challenge(
        &self,
        session_id: &SessionId,
        push_challenge: &str,
    ) -> Result<RegistrationOutput, Self::Error<UpdateSessionError>> {
        submit_request(
            &self.0,
            RegistrationRequest {
                session_id,
                request: UpdateRegistrationSession {
                    push_challenge: Some(push_challenge),
                    ..Default::default()
                },
            },
        )
        .await
    }

    async fn submit_verification_code(
        &self,
        session_id: &SessionId,
        code: &str,
    ) -> Result<RegistrationOutput, Self::Error<SubmitVerificationError>> {
        submit_request(
            &self.0,
            RegistrationRequest {
                session_id,
                request: SubmitVerificationCode { code },
            },
        )
        .await
    }

    async fn check_svr2_credentials(
        &self,
        number: &str,
        svr_tokens: &[String],
    ) -> Result<CheckSvr2CredentialsResponse, Self::Error<CheckSvr2CredentialsError>> {
        let request = CheckSvr2CredentialsRequest {
            number,
            tokens: svr_tokens,
        };
        let response = self
            .0
            .send(request.into())
            .await
            .map_err(SendError::into_request_error)?;
        response.try_into_response().map_err(Into::into)
    }

    async fn register_account(
        &self,
        number: &str,
        session_id: Option<&SessionId>,
        message_notification: NewMessageNotification<&str>,
        account_attributes: ProvidedAccountAttributes<'_>,
        device_transfer: Option<SkipDeviceTransfer>,
        keys: ForServiceIds<AccountKeys<'_>>,
        account_password: &str,
    ) -> Result<RegisterAccountResponse, Self::Error<RegisterAccountError>> {
        let request = ChatRequest::register_account(
            number,
            session_id,
            message_notification,
            account_attributes,
            device_transfer,
            keys,
            account_password,
        );

        let response = self
            .0
            .send(request)
            .await
            .map_err(SendError::into_request_error)?;

        response.try_into_response().map_err(Into::into)
    }
}

/// Sends a request for an established session.
///
/// On success, the state of the session as reported by the server is saved
/// (and accessible via [`Self::session_state`]). This method will retry
/// internally if transient errors are encountered.
async fn submit_request<R, E, C>(
    connection: &C,
    request: R,
) -> Result<RegistrationOutput, RequestError<E, <C::SendError as SendError>::DisconnectError>>
where
    R: Into<ChatRequest> + Send,
    RequestError<E, <C::SendError as SendError>::DisconnectError>:
        From<InvalidSessionId> + From<ResponseError>,
    C: WsClient<SendError: SendError> + Sync,
{
    let response = connection
        .send(request.into())
        .await
        .map_err(SendError::into_request_error)?;
    let response: crate::ws::registration::request::RegistrationResponse =
        response.try_into_response()?;

    response.try_into().map_err(Into::into)
}

const CONTENT_TYPE_JSON: (HeaderName, HeaderValue) =
    (http::header::CONTENT_TYPE, JSON_CONTENT_TYPE);
