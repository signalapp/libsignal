use bytes::Bytes;
use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use libsignal_net::auth::Auth;
use libsignal_net::chat::{LanguageList, Request as ChatRequest};
use libsignal_net::infra::AsHttpHeader as _;
use libsignal_protocol::PublicKey;
use serde_with::{FromInto, serde_as, skip_serializing_none};

use crate::api::registration::{
    AccountKeys, CreateSession, ForServiceIds, InvalidSessionId, NewMessageNotification,
    ProvidedAccountAttributes, PushToken, RegistrationLock, RegistrationSession, SessionId,
    SignedPreKeyBody, SkipDeviceTransfer, VerificationCodeNotDeliverable, VerificationTransport,
};
use crate::ws::CONTENT_TYPE_JSON;

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetSession {}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateRegistrationSession<'a> {
    pub(super) captcha: Option<&'a str>,
    #[serde(flatten)]
    pub(super) push_token: Option<&'a PushToken>,
    pub(super) push_challenge: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RequestVerificationCode<'a> {
    pub(super) transport: VerificationTransport,
    pub(super) client: &'a str,
    #[serde(skip)]
    pub(crate) language_list: LanguageList,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SubmitVerificationCode<'a> {
    pub(super) code: &'a str,
}

pub(super) struct RegistrationRequest<'s, R> {
    pub(super) session_id: &'s SessionId,
    pub(super) request: R,
}

impl<R: Request> RegistrationRequest<'_, R> {
    pub(super) fn log_safe_path(&self) -> String {
        R::log_safe_path(self.session_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(super) struct CheckSvr2CredentialsRequest<'s> {
    pub(super) number: &'s str,
    pub(super) tokens: &'s [String],
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountAttributes<'a> {
    fetches_messages: bool,
    #[serde(flatten)]
    account_attributes: ProvidedAccountAttributes<'a>,
}

#[serde_as]
#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Serialize, strum::EnumTryAs)]
#[serde(rename_all = "camelCase")]
enum SessionValidation<'a> {
    SessionId(&'a SessionId),
    RecoveryPassword(#[serde_as(as = "Base64Padded")] &'a [u8]),
}

impl VerificationCodeNotDeliverable {
    pub(super) fn from_response(
        response_headers: &HeaderMap,
        response_body: &[u8],
    ) -> Option<Self> {
        if response_headers.get(CONTENT_TYPE_JSON.0) != Some(&CONTENT_TYPE_JSON.1) {
            return None;
        }

        serde_json::from_slice(response_body).ok()
    }
}

impl RegistrationLock {
    pub(super) fn from_response(
        response_headers: &HeaderMap,
        response_body: &[u8],
    ) -> Option<Self> {
        if response_headers.get(CONTENT_TYPE_JSON.0) != Some(&CONTENT_TYPE_JSON.1) {
            return None;
        }

        serde_json::from_slice(response_body).ok()
    }
}

#[derive(Debug, Default, PartialEq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize), visibility::make(pub(crate)))]
#[serde(rename_all = "camelCase")]
pub(super) struct RegistrationResponse {
    #[serde(rename = "id")]
    pub(crate) session_id: String,
    #[serde(flatten)]
    pub(crate) session: RegistrationSession,
}

impl TryFrom<RegistrationResponse> for crate::api::registration::RegistrationResponse {
    type Error = InvalidSessionId;
    fn try_from(value: RegistrationResponse) -> Result<Self, Self::Error> {
        let RegistrationResponse {
            session_id,
            session,
        } = value;
        Ok(Self {
            session,
            session_id: SessionId::new(session_id)?,
        })
    }
}

/// A value that can be sent to the server as part of a REST request.
pub(super) trait Request {
    /// The HTTP [`Method`] to send the request with
    const METHOD: Method;

    /// The HTTP path to use when sending the request.
    fn request_path(session_id: &SessionId) -> PathAndQuery;

    fn log_safe_path(session_id: &SessionId) -> String;

    fn headers<'s>(&'s self) -> impl Iterator<Item = (HeaderName, HeaderValue)> + 's
    where
        Self: 's,
    {
        std::iter::empty()
    }

    /// The serialized JSON for the request body, if any.
    fn to_json_body(&self) -> Option<Box<[u8]>>;
}

impl Request for GetSession {
    const METHOD: Method = Method::GET;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        format!(
            "{VERIFICATION_SESSION_PATH_PREFIX}/{}",
            session_id.as_url_path_segment()
        )
        .parse()
        .expect("valid path")
    }
    fn log_safe_path(session_id: &SessionId) -> String {
        format!("{VERIFICATION_SESSION_PATH_PREFIX}/{session_id}")
    }
    fn to_json_body(&self) -> Option<Box<[u8]>> {
        None
    }
}

impl Request for UpdateRegistrationSession<'_> {
    const METHOD: Method = Method::PATCH;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        GetSession::request_path(session_id)
    }
    fn log_safe_path(session_id: &SessionId) -> String {
        GetSession::log_safe_path(session_id)
    }
    fn to_json_body(&self) -> Option<Box<[u8]>> {
        Some(
            serde_json::to_vec(&self)
                .expect("no maps")
                .into_boxed_slice(),
        )
    }
}

impl Request for RequestVerificationCode<'_> {
    const METHOD: Method = Method::POST;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        SubmitVerificationCode::request_path(session_id)
    }
    fn log_safe_path(session_id: &SessionId) -> String {
        SubmitVerificationCode::log_safe_path(session_id)
    }

    fn headers<'s>(&'s self) -> impl Iterator<Item = (HeaderName, HeaderValue)> + 's
    where
        Self: 's,
    {
        self.language_list.clone().into_header().into_iter()
    }

    fn to_json_body(&self) -> Option<Box<[u8]>> {
        Some(
            serde_json::to_vec(&self)
                .expect("no maps")
                .into_boxed_slice(),
        )
    }
}

impl Request for SubmitVerificationCode<'_> {
    const METHOD: Method = Method::PUT;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        format!(
            "{VERIFICATION_SESSION_PATH_PREFIX}/{}/code",
            session_id.as_url_path_segment()
        )
        .parse()
        .expect("valid path")
    }
    fn log_safe_path(session_id: &SessionId) -> String {
        format!("{VERIFICATION_SESSION_PATH_PREFIX}/{session_id}/code")
    }
    fn to_json_body(&self) -> Option<Box<[u8]>> {
        Some(
            serde_json::to_vec(&self)
                .expect("no maps")
                .into_boxed_slice(),
        )
    }
}

impl From<CheckSvr2CredentialsRequest<'_>> for ChatRequest {
    fn from(value: CheckSvr2CredentialsRequest<'_>) -> Self {
        Self {
            method: Method::POST,
            path: PathAndQuery::from_static("/v2/backup/auth/check"),
            headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
            body: Some(serde_json::to_vec(&value).expect("no maps").into()),
        }
    }
}

pub(super) trait RegisterChatRequest {
    fn register_account(
        number: &str,
        session_id: Option<&SessionId>,
        message_notification: NewMessageNotification<&str>,
        account_attributes: ProvidedAccountAttributes<'_>,
        device_transfer: Option<SkipDeviceTransfer>,
        keys: ForServiceIds<AccountKeys<'_>>,
        account_password: &str,
    ) -> Self;
}

impl RegisterChatRequest for ChatRequest {
    fn register_account(
        number: &str,
        session_id: Option<&SessionId>,
        message_notification: NewMessageNotification<&str>,
        account_attributes: ProvidedAccountAttributes<'_>,
        device_transfer: Option<SkipDeviceTransfer>,
        keys: ForServiceIds<AccountKeys<'_>>,
        account_password: &str,
    ) -> Self {
        #[serde_as]
        #[skip_serializing_none]
        #[derive(Debug, serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RegisterAccount<'a> {
            #[serde(flatten)]
            session_validation: SessionValidation<'a>,
            account_attributes: AccountAttributes<'a>,
            skip_device_transfer: bool,
            #[serde_as(as = "FromInto<PublicKeyBytes>")]
            aci_identity_key: &'a PublicKey,
            #[serde_as(as = "FromInto<PublicKeyBytes>")]
            pni_identity_key: &'a PublicKey,
            aci_signed_pre_key: SignedPreKeyBody<&'a [u8]>,
            pni_signed_pre_key: SignedPreKeyBody<&'a [u8]>,
            aci_pq_last_resort_pre_key: SignedPreKeyBody<&'a [u8]>,
            pni_pq_last_resort_pre_key: SignedPreKeyBody<&'a [u8]>,
            // Intentionally not #[serde(flatten)]-ed
            push_token: Option<PushToken<'a>>,
        }

        #[derive(Debug, serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        enum PushToken<'a> {
            ApnRegistrationId(&'a str),
            GcmRegistrationId(&'a str),
        }

        let (fetches_messages, push_token) = match message_notification {
            NewMessageNotification::Apn(apn) => (false, Some(PushToken::ApnRegistrationId(apn))),
            NewMessageNotification::Gcm(gcm) => (false, Some(PushToken::GcmRegistrationId(gcm))),
            NewMessageNotification::WillFetchMessages => (true, None),
        };

        let session_validation = session_id.map(SessionValidation::SessionId).unwrap_or(
            SessionValidation::RecoveryPassword(account_attributes.recovery_password),
        );

        let register_account = RegisterAccount {
            session_validation,
            account_attributes: AccountAttributes {
                account_attributes,
                fetches_messages,
            },
            skip_device_transfer: device_transfer.is_some_and(|SkipDeviceTransfer| true),
            aci_identity_key: keys.aci.identity_key,
            pni_identity_key: keys.pni.identity_key,
            aci_signed_pre_key: keys.aci.signed_pre_key,
            pni_signed_pre_key: keys.pni.signed_pre_key,
            aci_pq_last_resort_pre_key: keys.aci.pq_last_resort_pre_key,
            pni_pq_last_resort_pre_key: keys.pni.pq_last_resort_pre_key,
            push_token,
        };

        let body = Some(
            serde_json::to_vec(&register_account)
                .expect("no maps")
                .into(),
        );

        Self {
            method: Method::POST,
            headers: HeaderMap::from_iter([
                CONTENT_TYPE_JSON,
                Auth {
                    username: number,
                    password: account_password,
                }
                .as_header(),
            ]),
            path: PathAndQuery::from_static("/v1/registration"),
            body,
        }
    }
}

const VERIFICATION_SESSION_PATH_PREFIX: &str = "/v1/verification/session";

impl From<&CreateSession> for ChatRequest {
    fn from(value: &CreateSession) -> Self {
        let body = serde_json::to_vec(&value).expect("no maps").into();
        Self {
            method: Method::POST,
            headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
            path: PathAndQuery::from_static(VERIFICATION_SESSION_PATH_PREFIX),
            body: Some(body),
        }
    }
}

impl<'s, R: Request> From<RegistrationRequest<'s, R>> for ChatRequest {
    fn from(value: RegistrationRequest<'s, R>) -> Self {
        let RegistrationRequest {
            session_id,
            request,
        } = value;

        let path = R::request_path(session_id);
        let body = request.to_json_body().map(Bytes::from);
        let headers = request
            .headers()
            .chain(body.is_some().then_some(CONTENT_TYPE_JSON))
            .collect();

        Self {
            method: R::METHOD,
            headers,
            path,
            body,
        }
    }
}

type Base64Padded =
    serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>;

#[serde_as]
#[derive(serde::Serialize)]
#[serde(transparent)]
struct PublicKeyBytes(#[serde_as(as = "Base64Padded")] Box<[u8]>);

impl From<&PublicKey> for PublicKeyBytes {
    fn from(value: &PublicKey) -> Self {
        Self(value.serialize())
    }
}

#[cfg(test)]
impl RegistrationResponse {
    pub(crate) fn into_websocket_response(
        self,
        ws_request_id: u64,
    ) -> libsignal_net::proto::chat_websocket::WebSocketResponseMessage {
        libsignal_net::proto::chat_websocket::WebSocketResponseMessage {
            id: Some(ws_request_id),
            status: Some(http::StatusCode::OK.as_u16().into()),
            message: Some("OK".to_string()),
            headers: vec!["content-type: application/json".to_owned()],
            body: Some(serde_json::to_vec(&self).unwrap().into()),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr as _;
    use std::sync::LazyLock;
    use std::time::Duration;

    use base64::Engine;
    use http::StatusCode;
    use libsignal_core::{Aci, Pni};
    use libsignal_net::chat::Response as ChatResponse;
    use libsignal_protocol::{GenericSignedPreKey as _, KeyPair, KyberPreKeyRecord};
    use rand::SeedableRng as _;
    use serde_json::json;
    use uuid::uuid;

    use super::*;
    use crate::api::ChallengeOption;
    use crate::api::registration::{
        CheckSvr2CredentialsResponse, PushToken, RegisterAccountResponse, RegisterResponseBackup,
        RegisterResponseBadge, RegisterResponseEntitlements, Svr2CredentialsResult,
    };
    use crate::ws::TryIntoResponse as _;

    #[test]
    fn registration_create_session_request_as_chat_request() {
        let request: ChatRequest = (&CreateSession {
            number: "+18005550101".to_owned(),
            push_token: Some(PushToken::Apn {
                push_token: "someToken".to_owned(),
            }),
            mcc: Some("mcc".to_owned()),
            mnc: Some("mnc".to_owned()),
        })
            .into();

        assert_eq!(
            request,
            ChatRequest {
                method: Method::POST,
                path: PathAndQuery::from_static("/v1/verification/session"),
                headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: Some(Bytes::from_static(
                    br#"{"number":"+18005550101","pushTokenType":"apn","pushToken":"someToken","mcc":"mcc","mnc":"mnc"}"#
                ))
            }
        )
    }

    #[test]
    fn registration_get_session_request_as_chat_request() {
        let request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: GetSession {},
        }
        .into();

        assert_eq!(
            request,
            ChatRequest {
                method: Method::GET,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee"),
                headers: HeaderMap::default(),
                body: None,
            }
        )
    }

    #[test]
    fn registration_update_session_request_as_chat_request() {
        let captcha_request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: UpdateRegistrationSession {
                captcha: Some("captcha"),
                ..Default::default()
            },
        }
        .into();

        assert_eq!(
            captcha_request,
            ChatRequest {
                method: Method::PATCH,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee"),
                headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: Some(b"{\"captcha\":\"captcha\"}".as_slice().into())
            }
        );

        let captcha_request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: UpdateRegistrationSession {
                push_token: Some(&PushToken::Apn {
                    push_token: "token".to_owned(),
                }),
                ..Default::default()
            },
        }
        .into();

        assert_eq!(
            captcha_request,
            ChatRequest {
                method: Method::PATCH,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee"),
                headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: Some(
                    b"{\"pushTokenType\":\"apn\",\"pushToken\":\"token\"}"
                        .as_slice()
                        .into()
                )
            }
        )
    }

    #[test]
    fn registration_request_verification_as_chat_request() {
        let captcha_request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: RequestVerificationCode {
                transport: VerificationTransport::Sms,
                client: "client name",
                language_list: LanguageList::parse(&["tlh", "qya"]).expect("valid"),
            },
        }
        .into();

        assert_eq!(
            captcha_request,
            ChatRequest {
                method: Method::POST,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee/code"),
                headers: HeaderMap::from_iter([
                    CONTENT_TYPE_JSON,
                    (
                        "accept-language".parse().unwrap(),
                        "tlh,qya".parse().unwrap()
                    )
                ]),
                body: Some(
                    b"{\"transport\":\"sms\",\"client\":\"client name\"}"
                        .as_slice()
                        .into()
                )
            }
        );
    }

    #[test]
    fn registration_response_deserialize() {
        const RESPONSE_JSON: &str = r#"{
                "id": "fivesixseven",
                "allowedToRequestCode": true,
                "verified": true,
                "requestedInformation": ["pushChallenge", "captcha"]
            }"#;
        let response: RegistrationResponse = ChatResponse {
            status: StatusCode::OK,
            message: Some("OK".to_owned()),
            headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
            body: Some(RESPONSE_JSON.as_bytes().into()),
        }
        .try_into_response()
        .unwrap();

        assert_eq!(
            response,
            RegistrationResponse {
                session_id: "fivesixseven".parse().unwrap(),
                session: RegistrationSession {
                    allowed_to_request_code: true,
                    verified: true,
                    next_sms: None,
                    next_call: None,
                    next_verification_attempt: None,
                    requested_information: HashSet::from([
                        ChallengeOption::Captcha,
                        ChallengeOption::PushChallenge
                    ]),
                }
            }
        );
    }

    #[test]
    fn check_svr2_credentials_request() {
        let request = CheckSvr2CredentialsRequest {
            number: "+18005550123",
            tokens: &["user:pass1", "user:pass2", "user:pass3"].map(ToOwned::to_owned),
        };
        // Don't bother duplicating the impl by checking other fields
        let ChatRequest { body, .. } = request.into();
        assert_eq!(
            body.as_deref(),
            Some(
                serde_json::json!({
                    "number": "+18005550123",
                    "tokens": [
                        "user:pass1",
                        "user:pass2",
                        "user:pass3",
                    ]
                })
                .to_string()
                .as_bytes()
            )
        )
    }

    #[test]
    fn check_svr2_credentials_response_parse() {
        const RESPONSE_JSON: &str = r#" {
            "matches": {
                "property1": "match",
                "property2": "match"
            }
        } "#;

        let CheckSvr2CredentialsResponse { matches } =
            serde_json::from_str(RESPONSE_JSON).expect("parses");

        assert_eq!(
            matches,
            HashMap::from_iter(
                [
                    ("property1", Svr2CredentialsResult::Match),
                    ("property2", Svr2CredentialsResult::Match)
                ]
                .map(|(k, v)| (k.to_owned(), v))
            )
        )
    }

    static ACCOUNT_ATTRIBUTES: LazyLock<ProvidedAccountAttributes<'static>> =
        LazyLock::new(|| ProvidedAccountAttributes {
            recovery_password: b"recovery",
            registration_id: 123,
            pni_registration_id: 456,
            name: Some(b"device name proto"),
            registration_lock: Some("reg lock"),
            unidentified_access_key: b"unidentified key",
            unrestricted_unidentified_access: true,
            capabilities: HashSet::from(["can wear cape"]),
            discoverable_by_phone_number: true,
        });

    struct OwnedAccountKeys {
        identity_key: PublicKey,
        signed_pre_key: SignedPreKeyBody<Box<[u8]>>,
        pq_last_resort_pre_key: SignedPreKeyBody<Box<[u8]>>,
    }

    impl OwnedAccountKeys {
        fn as_borrowed(&self) -> AccountKeys<'_> {
            let Self {
                identity_key,
                signed_pre_key,
                pq_last_resort_pre_key,
            } = self;
            AccountKeys {
                identity_key,
                signed_pre_key: signed_pre_key.as_deref(),
                pq_last_resort_pre_key: pq_last_resort_pre_key.as_deref(),
            }
        }
    }

    static REGISTER_KEYS: LazyLock<ForServiceIds<OwnedAccountKeys>> = LazyLock::new(|| {
        // Use a seeded RNG for deterministic generation.
        let mut rng = rand_chacha::ChaChaRng::from_seed([1; 32]);

        ForServiceIds::generate(|_| {
            let identity_key = KeyPair::generate(&mut rng).public_key;

            let signed_pre_key = {
                let key_pair = KeyPair::generate(&mut rng);
                SignedPreKeyBody {
                    key_id: 1,
                    public_key: key_pair.public_key.serialize(),
                    signature: (*b"signature").into(),
                }
            };
            let pq_last_resort_pre_key = {
                let kem_keypair = libsignal_protocol::kem::KeyPair::generate(
                    libsignal_protocol::kem::KeyType::Kyber1024,
                    &mut rng,
                );
                let record = KyberPreKeyRecord::new(
                    1.into(),
                    libsignal_protocol::Timestamp::from_epoch_millis(42),
                    &kem_keypair,
                    b"signature",
                );
                SignedPreKeyBody {
                    key_id: 1,
                    public_key: Box::from(record.get_storage().public_key.clone()),
                    signature: Box::from(record.get_storage().signature.clone()),
                }
            };

            OwnedAccountKeys {
                identity_key,
                signed_pre_key,
                pq_last_resort_pre_key,
            }
        })
    });

    /// "Golden" test that makes sure the auto-generated serialization code ends
    /// up producing the JSON we expect.
    #[test]
    fn register_account_request() {
        let request = ChatRequest::register_account(
            "+18005550101",
            Some(&"abc".parse().unwrap()),
            NewMessageNotification::Apn("appleId"),
            ACCOUNT_ATTRIBUTES.clone(),
            Some(SkipDeviceTransfer),
            ForServiceIds::generate(|kind| REGISTER_KEYS.get(kind).as_borrowed()),
            "encoded account password",
        );

        const ENCODED_BASIC_AUTH: &str = "KzE4MDA1NTUwMTAxOmVuY29kZWQgYWNjb3VudCBwYXNzd29yZA==";
        // Assert as a means of explaining where this value comes from.
        assert_eq!(
            ENCODED_BASIC_AUTH,
            base64::prelude::BASE64_STANDARD.encode(b"+18005550101:encoded account password")
        );

        let ChatRequest {
            method,
            body,
            headers,
            path,
        } = request;
        assert_eq!(path, "/v1/registration");
        assert_eq!(
            (method, headers),
            (
                Method::POST,
                HeaderMap::from_iter(
                    [
                        ("content-type", "application/json"),
                        (
                            "authorization",
                            const_str::concat!("Basic ", ENCODED_BASIC_AUTH),
                        )
                    ]
                    .into_iter()
                    .map(|(a, b)| (a.parse().unwrap(), b.parse().unwrap()))
                )
            )
        );
        let body = serde_json::from_slice::<'_, serde_json::Value>(&body.unwrap()).unwrap();
        print!(
            "actual body: {}",
            serde_json::to_string_pretty(&body).unwrap()
        );

        pretty_assertions::assert_eq!(
            body,
            json!({
              "accountAttributes": {
                "capabilities": {
                  "can wear cape": true
                },
                "discoverableByPhoneNumber": true,
                "fetchesMessages": false,
                "name": "ZGV2aWNlIG5hbWUgcHJvdG8=",
                "pniRegistrationId": 456,
                "recoveryPassword": "cmVjb3Zlcnk=",
                "registrationId": 123,
                "registrationLock": "reg lock",
                "unidentifiedAccessKey": [ 117, 110, 105, 100, 101, 110, 116, 105, 102, 105, 101, 100, 32, 107, 101, 121 ],
                "unrestrictedUnidentifiedAccess": true
              },
              "aciIdentityKey": "BdU7n+od1NVw2+OBgHZ8I2RWymYz8QPxqgY357YT0lJ0",
              "pniIdentityKey": "BYUaOAA2JBxAXm0FEShgyoAvouVIKheoHGSCRtKXtR4T",
              "aciSignedPreKey": {
                "keyId": 1,
                "publicKey": "BQkeh2V1eV9fztQ/985a5lLbIeNFPGsexdO9I7HsQQZV",
                "signature": "c2lnbmF0dXJl"
              },
              "pniSignedPreKey": {
                "keyId": 1,
                "publicKey": "BeMJD5ri/FBr3/zaIzZ94XpgemAejHLtHgniY0LIx94s",
                "signature": "c2lnbmF0dXJl"
              },
              "pushToken": {
                "apnRegistrationId": "appleId"
              },
              "sessionId": "abc",
              "skipDeviceTransfer": true,
              "aciPqLastResortPreKey": "",
              "aciPqLastResortPreKey": {
                "keyId": 1,
                "publicKey": "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",
                "signature": "c2lnbmF0dXJl",
              },
              "pniPqLastResortPreKey": {
                "keyId": 1,
                "publicKey": "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",
                "signature": "c2lnbmF0dXJl",
              },
            })
        );
    }

    #[test]
    fn register_account_request_fetches_messages_no_push_tokens() {
        let request = ChatRequest::register_account(
            "+18005550101",
            Some(&"abc".parse().unwrap()),
            NewMessageNotification::WillFetchMessages,
            ACCOUNT_ATTRIBUTES.clone(),
            Some(SkipDeviceTransfer),
            ForServiceIds::generate(|kind| REGISTER_KEYS.get(kind).as_borrowed()),
            "encoded account password",
        );

        let body = serde_json::from_slice::<'_, serde_json::Value>(&request.body.unwrap()).unwrap();

        assert_eq!(
            body.get("accountAttributes")
                .and_then(|v| v.get("fetchesMessages")),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(body.get("pushToken"), None);
    }

    #[test]
    fn register_account_response_parse() {
        const RESPONSE_JSON: &str = r#" {
            "uuid": "095be615-a8ad-4c33-8e9c-c7612fbf6c9f",
            "number": "+18005550123",
            "pni": "06d9ee19-7126-49ad-b4cb-de1a4d42305a",
            "usernameHash": "YWJjZGVmZ2hp",
            "usernameLinkHandle": "431ca581-2806-466f-a4a3-4492d3c9a64b",
            "storageCapable": true,
            "entitlements": {
                "badges": [
                    {
                        "id": "badge-1",
                        "visible": true,
                        "expirationSeconds": 123456789
                    }
                ],
                "backup": {
                    "backupLevel": 555,
                    "expirationSeconds": 987654321
                }
            },
            "reregistration": true,
            "unknownFieldShouldBeIgnored": "Make sure that additional fields don't cause the response to be rejected."
        } "#;

        let response: RegisterAccountResponse = serde_json::from_str(RESPONSE_JSON).unwrap();

        assert_eq!(
            response,
            RegisterAccountResponse {
                aci: Aci::from(uuid!("095be615-a8ad-4c33-8e9c-c7612fbf6c9f")),
                number: "+18005550123".to_owned(),
                pni: Pni::from(uuid!("06d9ee19-7126-49ad-b4cb-de1a4d42305a")),
                username_hash: Some((*b"abcdefghi").into()),
                username_link_handle: Some(uuid!("431ca581-2806-466f-a4a3-4492d3c9a64b")),
                storage_capable: true,
                entitlements: RegisterResponseEntitlements {
                    badges: [RegisterResponseBadge {
                        id: "badge-1".to_owned(),
                        visible: true,
                        expiration: Duration::from_secs(123456789),
                    }]
                    .into(),
                    backup: Some(RegisterResponseBackup {
                        backup_level: 555,
                        expiration: Duration::from_secs(987654321),
                    })
                },
                reregistration: true,
            }
        )
    }
}
