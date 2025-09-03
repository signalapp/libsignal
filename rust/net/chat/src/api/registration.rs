//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::str::FromStr;
use std::time::Duration;

use libsignal_core::{Aci, Pni, ServiceIdKind};
use libsignal_net::auth::Auth;
use libsignal_net::chat::LanguageList;
use libsignal_protocol::{GenericSignedPreKey, PublicKey};
use serde_with::{
    DurationMilliSeconds, DurationSeconds, FromInto, serde_as, skip_serializing_none,
};
use uuid::Uuid;

mod error;
pub use error::*;

mod session_id;
pub use session_id::{InvalidSessionId, SessionId};

use crate::api::ChallengeOption;

pub type UnidentifiedAccessKey = [u8; zkgroup::ACCESS_KEY_LEN];

pub(crate) trait RegistrationChatApi {
    type Error<E>;
    fn create_session(
        &self,
        create_session: &CreateSession,
    ) -> impl Future<Output = Result<RegistrationResponse, Self::Error<CreateSessionError>>> + Send;

    fn get_session(
        &self,
        session_id: &SessionId,
    ) -> impl Future<Output = Result<RegistrationResponse, Self::Error<ResumeSessionError>>> + Send;

    fn submit_captcha(
        &self,
        session_id: &SessionId,
        captcha_value: &str,
    ) -> impl Future<Output = Result<RegistrationResponse, Self::Error<UpdateSessionError>>> + Send;

    fn request_push_challenge(
        &self,
        session_id: &SessionId,
        push_token: &PushToken,
    ) -> impl Future<Output = Result<RegistrationResponse, Self::Error<UpdateSessionError>>> + Send;

    fn request_verification_code(
        &self,
        session_id: &SessionId,
        transport: VerificationTransport,
        client: &str,
        languages: LanguageList,
    ) -> impl Future<
        Output = Result<RegistrationResponse, Self::Error<RequestVerificationCodeError>>,
    > + Send;

    fn submit_push_challenge(
        &self,
        session_id: &SessionId,
        push_challenge: &str,
    ) -> impl Future<Output = Result<RegistrationResponse, Self::Error<UpdateSessionError>>> + Send;

    fn submit_verification_code(
        &self,
        session_id: &SessionId,
        code: &str,
    ) -> impl Future<Output = Result<RegistrationResponse, Self::Error<SubmitVerificationError>>> + Send;

    fn check_svr2_credentials(
        &self,
        number: &str,
        svr_tokens: &[String],
    ) -> impl Future<
        Output = Result<CheckSvr2CredentialsResponse, Self::Error<CheckSvr2CredentialsError>>,
    > + Send;

    fn register_account(
        &self,
        number: &str,
        session_id: Option<&SessionId>,
        message_notification: NewMessageNotification<&str>,
        account_attributes: ProvidedAccountAttributes<'_>,
        device_transfer: Option<SkipDeviceTransfer>,
        keys: ForServiceIds<AccountKeys<'_>>,
        account_password: &str,
    ) -> impl Future<Output = Result<RegisterAccountResponse, Self::Error<RegisterAccountError>>> + Send;
}

#[derive(Debug, PartialEq)]
pub(crate) struct RegistrationResponse {
    pub(crate) session_id: SessionId,
    pub(crate) session: RegistrationSession,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSession {
    pub number: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub push_token: Option<PushToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnc: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "pushTokenType", rename_all = "camelCase")]
pub enum PushToken {
    Apn {
        #[serde(rename = "pushToken")]
        push_token: String,
    },
    Fcm {
        #[serde(rename = "pushToken")]
        push_token: String,
    },
}

#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase", default)]
pub struct RegistrationSession {
    pub allowed_to_request_code: bool,
    pub verified: bool,
    #[serde_as(as = "Option<DurationSeconds>")]
    pub next_sms: Option<Duration>,
    #[serde_as(as = "Option<DurationSeconds>")]
    pub next_call: Option<Duration>,
    #[serde_as(as = "Option<DurationSeconds>")]
    pub next_verification_attempt: Option<Duration>,
    #[serde_as(as = "HashSet<serde_with::DisplayFromStr>")]
    pub requested_information: HashSet<ChallengeOption>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, strum::EnumString)]
#[strum(serialize_all = "camelCase")]
#[serde(rename_all = "camelCase")]
pub enum VerificationTransport {
    Sms,
    Voice,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VerificationCodeNotDeliverable {
    // This could be a stronger type but we don't need it to be in libsignal and
    // the additional flexibility could be useful if the server adds more
    // "reason" values.
    pub reason: String,
    pub permanent_failure: bool,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, serde::Deserialize, derive_more::Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationLock {
    #[serde_as(as = "DurationMilliSeconds")]
    pub time_remaining: Duration,
    #[debug("_")]
    pub svr2_credentials: Auth,
}

/// The subset of account attributes that don't need any additional validation.
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProvidedAccountAttributes<'a> {
    #[serde_as(as = "Base64Padded")]
    pub recovery_password: &'a [u8],
    /// Generated ID associated with a user's ACI.
    pub registration_id: u16,
    /// Generated ID associated with a user's PNI.
    pub pni_registration_id: u16,
    /// Protobuf-encoded device name.
    #[serde_as(as = "Option<Base64Padded>")]
    pub name: Option<&'a [u8]>,
    pub registration_lock: Option<&'a str>,
    /// Generated from the user's profile key.
    pub unidentified_access_key: &'a UnidentifiedAccessKey,
    /// Whether the user allows sealed sender messages to come from arbitrary senders.
    pub unrestricted_unidentified_access: bool,
    #[serde_as(as = "MappedToTrue")]
    pub capabilities: HashSet<&'a str>,
    pub discoverable_by_phone_number: bool,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAccountResponse {
    /// The account identifier for this account.
    #[serde_as(as = "FromInto<Uuid>")]
    #[serde(rename = "uuid")]
    pub aci: Aci,
    /// The phone number associated with this account.
    pub number: String,
    /// The account identifier for this account's phone-number identity.
    #[serde_as(as = "FromInto<Uuid>")]
    pub pni: Pni,
    /// A hash of this account's username, if set.
    #[serde_as(as = "Option<Base64Padded>")]
    pub username_hash: Option<Box<[u8]>>,
    /// The account's username link handle, if set.
    pub username_link_handle: Option<Uuid>,
    /// Whether any of this account's devices support storage.
    #[serde(default)]
    pub storage_capable: bool,
    /// Entitlements for this account and their current expirations.
    #[serde(default)]
    pub entitlements: RegisterResponseEntitlements,
    /// If true, there was an existing account registered for this number.
    #[serde(default)]
    pub reregistration: bool,
}

#[serde_as]
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponseEntitlements {
    /// Active badges.
    pub badges: Box<[RegisterResponseBadge]>,
    /// If present, the backup level set.
    pub backup: Option<RegisterResponseBackup>,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponseBadge {
    /// The badge ID.
    pub id: String,
    /// Whether the badge is currently configured to be visible.
    pub visible: bool,
    /// When the badge expires.
    #[serde_as(as = "DurationSeconds")]
    #[serde(rename = "expirationSeconds")]
    pub expiration: Duration,
}

#[serde_as]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponseBackup {
    /// The backup level of the account.
    pub backup_level: u64,
    /// When the backup entitlement expires.
    #[serde_as(as = "DurationSeconds")]
    #[serde(rename = "expirationSeconds")]
    pub expiration: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct CheckSvr2CredentialsResponse {
    pub matches: HashMap<String, Svr2CredentialsResult>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Deserialize, strum::AsRefStr)]
#[strum(serialize_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum Svr2CredentialsResult {
    Match,
    NoMatch,
    Invalid,
}

/// Pair of values where one is for an ACI and the other a PNI.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Default)]
pub struct ForServiceIds<T> {
    pub aci: T,
    pub pni: T,
}

/// Keys associated with a single service ID for an account.
pub struct AccountKeys<'a> {
    pub identity_key: &'a PublicKey,
    pub signed_pre_key: SignedPreKeyBody<&'a [u8]>,
    pub pq_last_resort_pre_key: SignedPreKeyBody<&'a [u8]>,
}

/// How a device wants to be notified of messages when offline.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum NewMessageNotification<S> {
    /// Use the provided APN ID to receive push notifications.
    Apn(S),
    /// Use the provided GCM/FCM ID to receive push notifications.
    Gcm(S),
    /// The device will poll on its own.
    #[default]
    WillFetchMessages,
}

impl<T> ForServiceIds<T> {
    pub fn get_mut(&mut self, kind: ServiceIdKind) -> &mut T {
        match kind {
            ServiceIdKind::Aci => &mut self.aci,
            ServiceIdKind::Pni => &mut self.pni,
        }
    }

    pub fn get(&self, kind: ServiceIdKind) -> &T {
        match kind {
            ServiceIdKind::Aci => &self.aci,
            ServiceIdKind::Pni => &self.pni,
        }
    }

    pub fn generate(mut f: impl FnMut(libsignal_core::ServiceIdKind) -> T) -> Self {
        ForServiceIds {
            aci: f(libsignal_core::ServiceIdKind::Aci),
            pni: f(libsignal_core::ServiceIdKind::Pni),
        }
    }
}

impl<S> NewMessageNotification<S> {
    pub fn as_deref(&self) -> NewMessageNotification<&S::Target>
    where
        S: std::ops::Deref,
    {
        match self {
            Self::Apn(apn) => NewMessageNotification::Apn(apn),
            Self::Gcm(gcm) => NewMessageNotification::Gcm(gcm),
            Self::WillFetchMessages => NewMessageNotification::WillFetchMessages,
        }
    }
}

/// Marker type to indicate that device transfer is being intentionally skipped.
///
/// This is usually used as `Option<SkipDeviceTransfer>` in place of a boolean
/// value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SkipDeviceTransfer;

type Base64Padded =
    serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>;

#[serde_as]
#[derive(Copy, Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", bound = "B: AsRef<[u8]>")]
pub struct SignedPreKeyBody<B> {
    pub key_id: u32,
    #[serde_as(as = "Base64Padded")]
    pub public_key: B,
    #[serde_as(as = "Base64Padded")]
    pub signature: B,
}

impl<'a, T: GenericSignedPreKey> From<&'a T> for SignedPreKeyBody<&'a [u8]> {
    fn from(record: &'a T) -> Self {
        let storage = record.get_storage();
        Self {
            key_id: storage.id,
            public_key: &storage.public_key,
            signature: &storage.signature,
        }
    }
}

impl<T> SignedPreKeyBody<T> {
    pub fn to_owned(&self) -> SignedPreKeyBody<T::Owned>
    where
        T: ToOwned,
    {
        let Self {
            key_id,
            public_key,
            signature,
        } = self;
        SignedPreKeyBody {
            key_id: *key_id,
            public_key: public_key.to_owned(),
            signature: signature.to_owned(),
        }
    }

    pub fn as_deref(&self) -> SignedPreKeyBody<&T::Target>
    where
        T: std::ops::Deref,
    {
        let Self {
            key_id,
            public_key,
            signature,
        } = self;
        SignedPreKeyBody {
            key_id: *key_id,
            public_key,
            signature,
        }
    }
}

struct MappedToTrue;

impl<T> serde_with::SerializeAs<HashSet<T>> for MappedToTrue
where
    T: serde::Serialize,
{
    fn serialize_as<S>(source: &HashSet<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_map(source.iter().map(|name| (name, true)))
    }
}

impl TryFrom<String> for VerificationTransport {
    type Error = <Self as FromStr>::Err;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value)
    }
}
