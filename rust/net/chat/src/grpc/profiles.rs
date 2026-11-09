//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::time::SystemTime;

use async_trait::async_trait;
use displaydoc::Display;
use libsignal_core::{Aci, LogSafeDisplay, ServiceId};
use libsignal_net_grpc::proto::chat::account::accounts_anonymous_client::AccountsAnonymousClient;
use libsignal_net_grpc::proto::chat::account::{
    CheckAccountExistenceRequest, CheckAccountExistenceResponse,
};
use libsignal_net_grpc::proto::chat::errors::{self, FailedPrecondition};
use libsignal_net_grpc::proto::chat::profile::get_profile_key_credential_response::Response as GetProfileKeyCredentialResponseEnum;
use libsignal_net_grpc::proto::chat::profile::get_profile_response::Response as GetProfileResponseEnum;
use libsignal_net_grpc::proto::chat::profile::profile_anonymous_client::ProfileAnonymousClient;
use libsignal_net_grpc::proto::chat::profile::profile_client::ProfileClient;
use libsignal_net_grpc::proto::chat::profile::set_profile_response::Response as GrpcSetProfileResponse;
use libsignal_net_grpc::proto::chat::profile::{
    CredentialType, ExpectedVersionConflict, GetProfileKeyCredentialRequest,
    GetProfileKeyCredentialResponse, GetProfileKeyCredentialResult, GetProfileRequest,
    PaymentsForbiddenInRegion, SetProfileRequest, SetProfileResult, SetProfileV1Request,
};
use libsignal_protocol::IdentityKey;
use rand::CryptoRng;
use strum::VariantArray;
use zkgroup::profiles::{ProfileKey, ProfileKeyVersion};
use zkgroup::{PROFILE_KEY_VERSION_LEN, ProfileKeyBytes};

use crate::api::profiles::ProfileKeyCredentialRequestError;
use crate::api::{Auth, RequestError, Unauth};
use crate::grpc::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::impl_debug_from_display;
use crate::logging::Redact;

mod profile_utils;

pub type BadgeId = String;
pub type PaymentAddress = Vec<u8>;
pub type ProfileDataHash = [u8; 32];
pub const PROFILE_ETAG_LEN: usize = 10;
pub type ProfileEtag = [u8; PROFILE_ETAG_LEN];

/// A CDN URL.
///
/// It must point to a Signal CDN server.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct CdnUrl(String);

impl CdnUrl {
    // NOTE: the trailing slash is important! Otherwise someone could point at a non-signal domain
    pub const CDN0: &str = "https://cdn.signal.org/";
    pub const VALID_PREFIXES: &[&str] = &[
        Self::CDN0,
        "https://cdn2.signal.org/",
        "https://cdn3.signal.org/",
    ];
}

/// Invalid CDN URL
#[derive(Clone, Copy, Debug, PartialEq, Eq, Display)]
pub struct InvalidCdnUrl;
impl LogSafeDisplay for InvalidCdnUrl {}
impl TryFrom<String> for CdnUrl {
    type Error = InvalidCdnUrl;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !value.is_ascii() {
            log::warn!("CdnUrl isn't ASCII");
            return Err(InvalidCdnUrl);
        }
        if !Self::VALID_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
        {
            log::warn!("CdnUrl didn't start with any valid prefix.");
            return Err(InvalidCdnUrl);
        }
        Ok(CdnUrl(value))
    }
}

impl From<CdnUrl> for String {
    fn from(value: CdnUrl) -> Self {
        value.0
    }
}
impl AsRef<str> for CdnUrl {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Profile {
    /// Non-empty; max-length should be 128 bytes
    pub given_name: String,
    /// Optional (can be empty); max-length should be 128 bytes
    pub family_name: String,
    /// Optional (can be empty); max-length should be 512 bytes
    pub about: String,
    /// Optional (can be empty); max-length should be 32 bytes
    pub about_emoji: String,
    /// If provided, it should be the full URL to the avatar.
    pub avatar: Option<CdnUrl>,
    // The following fields are conceptually part of the user's profile, but live outside of the
    // encrypted v2 PlaintextProfileData
    pub phone_number_sharing: bool,
    pub payment_address: Option<PaymentAddress>,
    pub badge_ids: Vec<BadgeId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray)]
pub enum ProfileFieldWithMaxLength {
    GivenName,
    FamilyName,
    About,
    AboutEmoji,
    Avatar,
    PaymentAddress,
}
impl ProfileFieldWithMaxLength {
    /// The maximum allowable length of this field
    pub const fn max_length(&self) -> usize {
        match self {
            ProfileFieldWithMaxLength::GivenName => 128,
            ProfileFieldWithMaxLength::FamilyName => 128,
            ProfileFieldWithMaxLength::About => 512,
            ProfileFieldWithMaxLength::AboutEmoji => 32,
            ProfileFieldWithMaxLength::Avatar => 128,
            ProfileFieldWithMaxLength::PaymentAddress => 550,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Display)]
pub enum ProfileValidationError {
    /// Field {field:?} was {len} bytes ({max_len} is the maximum)
    FieldTooLong {
        field: ProfileFieldWithMaxLength,
        len: usize,
        max_len: usize,
    },
    /// The given name field cannot be empty
    GivenNameEmpty,
}
impl LogSafeDisplay for ProfileValidationError {}

impl Profile {
    /// Validate that a profile meets the validation rules.
    fn validate(&self) -> Result<(), ProfileValidationError> {
        use ProfileFieldWithMaxLength::*;
        use ProfileValidationError::*;
        if self.given_name.is_empty() {
            return Err(GivenNameEmpty);
        }
        for (field, len) in [
            (GivenName, self.given_name.len()),
            (FamilyName, self.family_name.len()),
            (About, self.about.len()),
            (AboutEmoji, self.about_emoji.len()),
            (
                Avatar,
                self.avatar
                    .as_ref()
                    .map(|url| url.as_ref().len())
                    .unwrap_or_default(),
            ),
            (
                PaymentAddress,
                self.payment_address
                    .as_ref()
                    .map(|addr| addr.len())
                    .unwrap_or_default(),
            ),
        ] {
            if len > field.max_length() {
                return Err(ProfileValidationError::FieldTooLong {
                    field,
                    len,
                    max_len: field.max_length(),
                });
            }
        }
        Ok(())
    }
}

/// The result of fetching a profile.
///
/// This contains the profile, itself, along with other associated information about the target
/// account.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct FetchedProfile {
    pub profile: Profile,
    /// This `etag` may be `None` if the profile isn't etag-able (e.g. if the account is still
    /// using a profiles v1 profile).
    pub etag: Option<ProfileEtag>,
    /// If the account has a v2 profile set, what's its data hash?
    pub v2_data_hash: Option<ProfileDataHash>,
    pub identity_key: IdentityKey,
    pub unidentified_access_key_fingerprint: Option<[u8; 32]>,
    pub unrestricted_unidentified_access: bool,
}

impl std::fmt::Display for Redact<CheckAccountExistenceRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(CheckAccountExistenceRequest { service_identifier }) = self;
        f.debug_struct("CheckAccountExistenceRequest")
            .field(
                "service_identifier",
                &service_identifier.as_ref().map(Redact),
            )
            .finish()
    }
}

impl std::fmt::Display for Redact<GetProfileKeyCredentialRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GetProfileKeyCredentialRequest {
            account_identifier,
            credential_request,
            credential_type,
            // This is fixed-length, somewhat sensitive, and not helpful for debugging.
            unidentified_access_key: _,
        }) = self;
        f.debug_struct("GetProfileKeyCredentialRequest")
            .field("aci", &account_identifier.as_ref().map(Redact))
            .field("credential_type", &credential_type)
            .field("credential_request.len()", &credential_request.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::profiles::UnauthenticatedAccountExistenceApi<OverGrpc>
    for Unauth<T>
{
    async fn account_exists(&self, account: ServiceId) -> Result<bool, RequestError<Infallible>> {
        let mut account_service = AccountsAnonymousClient::new(self.0.service());
        let request = CheckAccountExistenceRequest {
            service_identifier: Some(account.into()),
        };
        let log_safe_description = Redact(&request).to_string();
        let CheckAccountExistenceResponse { account_exists } =
            log_and_send(Self::LOG_TAG, &log_safe_description, || {
                account_service.check_account_existence(request)
            })
            .await?
            .into_inner();
        Ok(account_exists)
    }
}

#[derive(Debug, Clone, Display, PartialEq, Eq)]
/// The profile could not be successfully decoded.
///
/// This is an enum only for testing purposes. For security purposes, we don't want to allow
/// programatic introspection on the exact decode error.
enum ProfileDecodeError {
    /// The incoming profile was invalid due to {0}
    IncomingProfileValidationFailed(ProfileValidationError),
    /// Failed to protobuf decode the plaintext profile v2 data
    ProfileV2InvalidProtobuf,
    /// Invalid avatar URL: {0}
    InvalidAvatarUrl(InvalidCdnUrl),
    /// A profile v2 data buffer couldn't be un-padded because it was empty
    ProfileV2DataEmptyProfileBufferCannotContainPadding,
    /// A profile v2 data buffer couldn't be un-padded because the padding byte was 0 (i.e. the
    /// buffer used one byte of padding to report that there were zero bytes of padding).
    ProfileV2BufferZeroPadding,
    /// A profile v2 data buffer claimed it has {padding_size} bytes of padding, but it's only
    /// {buffer_size} long
    ProfileV2DataTooSmallForClaimedPadding {
        buffer_size: usize,
        padding_size: u8,
    },
    /// A profile data v2 buffer claimed padding size {padding_size}, but not all the bytes of
    /// padding were that size
    ProfileV2DataInvalidPaddingByte { padding_size: u8 },
    /// Profile v2 encrypted data of size {len}, is too small to have a nonce.
    ProfileV2DataTooSmallForNonce { len: usize },
    /// Profile v2 encrypted data failed decryption
    ProfileV2DataFailedDecryption,
    /// Profile v1 encrypted field {field:?} of size {len}, is too small to have a nonce.
    ProfileV1FieldTooSmallForNonce {
        field: profile_utils::v1::Field,
        len: usize,
    },
    /// Profile v1 encrypted field {field:?} failed decryption
    ProfileV1FieldFailedDecryption { field: profile_utils::v1::Field },
    /// Profile v1 field {field:?} isn't valid utf-8
    ProfileV1FieldInvalidUtf8 { field: profile_utils::v1::Field },
    /// Profile v1 field {field:?} doesn't encode a valid boolean
    ProfileV1FieldInvalidBoolean { field: profile_utils::v1::Field },
    /// Profile v1 field {field:?} is too short to encode a 4-byte length
    ProfileV1FieldTooShortToIncludeLength { field: profile_utils::v1::Field },
    /// Profile v1 field {field:?} ({len} bytes) is too short for the claimed {claimed} length
    ProfileV1FieldTooShortForLength {
        field: profile_utils::v1::Field,
        len: usize,
        claimed: usize,
    },
}
impl LogSafeDisplay for ProfileDecodeError
where
    InvalidCdnUrl: LogSafeDisplay,
    ProfileValidationError: LogSafeDisplay,
{
}

#[derive(Debug, Clone, Display, PartialEq, Eq)]
pub enum AuthProfileGetError {
    /// A profile could not be found
    ProfileNotFound,
    /// The profile could not be decoded: {log_safe}
    ProfileDecodeError { log_safe: String },
}

impl std::fmt::Display for Redact<GetProfileRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(GetProfileRequest {
            account_identifier,
            version: _,
            etag,
        }) = self;
        f.debug_struct("GetProfileRequest")
            .field(
                "account_identifier",
                &Redact(
                    account_identifier
                        .as_ref()
                        .expect("a service identifier is set"),
                ),
            )
            .field("etag.is_empty()", &etag.is_empty())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for Redact<SetProfileV1Request> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(SetProfileV1Request {
            name,
            avatar_change,
            about_emoji,
            about,
            phone_number_sharing,
        }) = self;
        f.debug_struct("SetProfileV1Request")
            .field("name.len()", &name.len())
            .field("avatar_change", &avatar_change)
            .field("about_emoji.len()", &about_emoji.len())
            .field("about.len()", &about.len())
            .field("phone_number_sharing.len()", &phone_number_sharing.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for Redact<SetProfileRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(SetProfileRequest {
            version: _,
            data,
            expected_current_data_hash,
            expected_current_version,
            payment_address,
            badge_ids,
            commitment: _,
            v1_request,
        }) = self;
        f.debug_struct("SetProfileRequest")
            .field("data.len()", &data.len())
            .field(
                "expected_current_data_hash.len()",
                &expected_current_data_hash.len(),
            )
            .field(
                "expected_current_version.len()",
                &expected_current_version.len(),
            )
            .field("payment_address.len()", &payment_address.len())
            .field("badge_ids.len()", &badge_ids.len())
            .field("v1_request", &v1_request.as_ref().map(Redact))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Display, PartialEq, Eq)]
pub enum SetProfileError {
    /// The given profile was invalid: {0}
    InvalidProfile(ProfileValidationError),
    /// The current data hash did not match the request's expectation, indicating
    /// another device on the account may have written an update the caller does not know about.
    ExpectedDataWriteConflict,
    /// The current version did not match the request's expectation, indicating
    /// another device on the account may have created a new version the caller does not know about.
    ExpectedVersionWriteConflict {
        /// In certain, highly unlikely, cases, a new profile version might not be
        /// distributed among all devices. These devices wouldn't be able to decrypt the
        /// profile, but the value can be used to set a new version.
        current_profile_version: Option<ProfileKeyVersion>,
    },
    /// Payments are not permitted in the account's region, based on its phone
    /// number or the caller's IP address if the account does not have a phone
    /// number. The request should be retried without `payment_address`.
    PaymentsForbiddenInRegion,
}
// We want to ensure that any current_profile_version doesn't get printed.
impl_debug_from_display!(SetProfileError);

impl<T: GrpcServiceProvider> Auth<T> {
    /// Retrieves profile data.
    ///
    /// Callers with an unidentified access key for the account should use the unauth version,
    /// instead.
    ///
    /// If an `etag` is provided, and the profile etag remains unchanged, this returns `None` to
    /// indicate that the profile was already up-to-date.
    pub async fn get_profile(
        &self,
        aci: Aci,
        profile_key: &ProfileKey,
        etag: Option<ProfileEtag>,
    ) -> Result<Option<FetchedProfile>, RequestError<AuthProfileGetError>> {
        let version = profile_key.get_profile_key_version(aci);
        let request = GetProfileRequest {
            account_identifier: Some(aci.into()),
            version: version.as_ref().to_vec(),
            etag: etag.map(|etag| etag.to_vec()).unwrap_or_default(),
        };
        let log_safe_description = Redact(&request).to_string();
        let mut profiles_service = ProfileClient::new(self.0.service());
        match log_and_send(Self::LOG_TAG, &log_safe_description, || {
            profiles_service.get_profile(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".into(),
        })? {
            GetProfileResponseEnum::Profile(profile_result) => {
                profile_utils::v2::decrypt_profile(profile_key, profile_result)
                    .map(Some)
                    .map_err(|e| match e {
                        profile_utils::Error::ProfileDecodeError(e) => {
                            RequestError::Other(AuthProfileGetError::ProfileDecodeError {
                                log_safe: e.log_safe_display().to_string(),
                            })
                        }
                        profile_utils::Error::Unexpected { log_safe } => {
                            RequestError::Unexpected { log_safe }
                        }
                    })
            }
            GetProfileResponseEnum::EtagMatched(true | false) => Ok(None),
            GetProfileResponseEnum::NotFound(errors::NotFound {}) => {
                Err(RequestError::Other(AuthProfileGetError::ProfileNotFound))
            }
            GetProfileResponseEnum::LegacyProfile(legacy_profile_result) => {
                profile_utils::v1::decrypt_profile(profile_key, &legacy_profile_result)
                    .map(Some)
                    .map_err(|e| match e {
                        profile_utils::Error::ProfileDecodeError(e) => {
                            RequestError::Other(AuthProfileGetError::ProfileDecodeError {
                                log_safe: e.log_safe_display().to_string(),
                            })
                        }
                        profile_utils::Error::Unexpected { log_safe } => {
                            RequestError::Unexpected { log_safe }
                        }
                    })
            }
        }
    }

    /// Set the profile for the current account.
    ///
    /// `expected_current_profile_key_version` must be the the current profile key version of the
    /// account (or `None` if there is no current version). In case of mismatch, the resulting
    /// error will contain the current profile key version, which may be passed into this parameter
    /// on a subsequent request.
    ///
    /// `expected_current_data_hash` must exactly match the server's view of the current profile v2
    /// data hash. When changing to a new profile key, `expected_current_data_hash` must be `None`.
    /// If this is the first v2 profile for this profile key, then `expected_current_data_hash`
    /// must be `None`. Otherwise, `expected_current_data_hash` must be the result of the _last_
    /// successful `set_profile` invocation _from across all devices on the account_.
    ///
    /// Note that if an older client (not yet using libsignal to set profiles) sets a v1 profile,
    /// this will clear out the v2 profile, and `expected_current_data_hash` should be `None` in
    /// these cases.
    ///
    /// The easiest way to obtain the correct `expected_current_data_hash` is to invoke
    /// `get_profile` on the current account. The resulting [`FetchedProfile`]'s `v2_data_hash`
    /// will be the correct value (regardless of whether it's `None` or not) to pass to the
    /// `expected_current_data_hash` argument of this function.
    pub async fn set_profile(
        &self,
        rng: &mut dyn CryptoRng,
        aci: Aci,
        profile_key: &ProfileKey,
        profile: Profile,
        expected_current_data_hash: Option<ProfileDataHash>,
        expected_current_profile_key_version: Option<&ProfileKeyVersion>,
    ) -> Result<ProfileDataHash, RequestError<SetProfileError>> {
        profile
            .validate()
            .map_err(|e| RequestError::Other(SetProfileError::InvalidProfile(e)))?;
        let (request, data_hash) = profile_utils::build_set_profile_request(
            rng,
            aci,
            profile_key,
            profile,
            expected_current_data_hash,
            expected_current_profile_key_version,
        );
        let log_safe_description = Redact(&request).to_string();
        let mut profiles_service = ProfileClient::new(self.0.service());
        match log_and_send(Self::LOG_TAG, &log_safe_description, || {
            profiles_service.set_profile(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".into(),
        })? {
            GrpcSetProfileResponse::Result(SetProfileResult {
                v1_avatar_upload_form: _,
            }) => Ok(data_hash),
            GrpcSetProfileResponse::ExpectedDataWriteConflict(FailedPrecondition {
                description: _,
            }) => Err(RequestError::Other(
                SetProfileError::ExpectedDataWriteConflict,
            )),
            GrpcSetProfileResponse::PaymentsForbiddenInRegion(PaymentsForbiddenInRegion {}) => Err(
                RequestError::Other(SetProfileError::PaymentsForbiddenInRegion),
            ),
            GrpcSetProfileResponse::ExpectedVersionWriteConflict(ExpectedVersionConflict {
                current_profile_version,
            }) => Err(RequestError::Other(
                SetProfileError::ExpectedVersionWriteConflict {
                    current_profile_version: if current_profile_version.is_empty() {
                        None
                    } else {
                        Some(ProfileKeyVersion {
                            bytes: *<&ProfileKeyBytes>::try_from(
                                current_profile_version.as_slice(),
                            )
                            .map_err(|_| RequestError::Unexpected {
                                log_safe: format!(
                                    "Expected {} bytes for profile key version, but got {}",
                                    PROFILE_KEY_VERSION_LEN,
                                    current_profile_version.len()
                                ),
                            })?,
                        })
                    },
                },
            )),
        }
    }
}

impl<T: GrpcServiceProvider> Unauth<T> {
    pub async fn get_profile_key_credential(
        &self,
        profile_key_request_context: zkgroup::profiles::ProfileKeyCredentialRequestContext,
        server_params: &zkgroup::ServerPublicParams,
    ) -> Result<
        zkgroup::profiles::ExpiringProfileKeyCredential,
        RequestError<ProfileKeyCredentialRequestError>,
    > {
        let request = GetProfileKeyCredentialRequest {
            account_identifier: Some(profile_key_request_context.aci().into()),
            credential_request: zkgroup::serialize(&profile_key_request_context.get_request()),
            credential_type: CredentialType::ExpiringProfileKey.into(),
            unidentified_access_key: profile_key_request_context
                .profile_key()
                .derive_access_key()
                .to_vec(),
        };
        let log_safe_description = Redact(&request).to_string();

        let mut profiles_service = ProfileAnonymousClient::new(self.0.service());
        let GetProfileKeyCredentialResponse { response } =
            log_and_send(Self::LOG_TAG, &log_safe_description, || {
                profiles_service.get_profile_key_credential(request)
            })
            .await?
            .into_inner();
        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        match response {
            GetProfileKeyCredentialResponseEnum::Result(GetProfileKeyCredentialResult {
                profile_key_credential,
            }) => {
                let zk_response = zkgroup::deserialize(&profile_key_credential).map_err(|e| {
                    RequestError::Unexpected {
                        log_safe: e.to_string(),
                    }
                })?;
                server_params
                    .receive_expiring_profile_key_credential(
                        &profile_key_request_context,
                        &zk_response,
                        SystemTime::now().into(),
                    )
                    .map_err(|e| RequestError::Unexpected {
                        log_safe: e.to_string(),
                    })
            }
            GetProfileKeyCredentialResponseEnum::NotFound(errors::NotFound {}) => Err(
                RequestError::Other(ProfileKeyCredentialRequestError::ProfileNotFound),
            ),
            GetProfileKeyCredentialResponseEnum::FailedUnidentifiedAuthorization(
                errors::FailedUnidentifiedAuthorization { description },
            ) => {
                log::warn!("failed auth: {description}");
                Err(RequestError::Other(
                    ProfileKeyCredentialRequestError::AuthFailed,
                ))
            }
        }
    }
}

pub mod test_cases {
    use libsignal_net_grpc::proto::chat::common::{IdentityType, ServiceIdentifier};
    use uuid::{Uuid, uuid};
    use zkgroup::SECONDS_PER_DAY;

    use super::*;
    use crate::grpc::GrpcTestCase;
    use crate::grpc::test_case_util::day_align;

    pub(crate) const ACI_UUID: Uuid = uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
    #[cfg(test)]
    pub(crate) const PNI_UUID: Uuid = uuid!("796abedb-ca4e-4f18-8803-1fde5b921f9f");

    #[derive(Clone)]
    pub struct GetProfileKeyCredentialArgs {
        pub profile_key_request_context: zkgroup::profiles::ProfileKeyCredentialRequestContext,
        pub server_params: zkgroup::ServerPublicParams,
    }
    #[allow(clippy::large_enum_variant)]
    pub enum GetProfileKeyCredentialOut {
        Success(zkgroup::profiles::ExpiringProfileKeyCredential),
        UnexpectedError { contains: &'static str },
        ExplicitError(ProfileKeyCredentialRequestError),
    }

    pub fn get_profile_key_credential_test_cases() -> Vec<
        GrpcTestCase<
            GetProfileKeyCredentialArgs,
            GetProfileKeyCredentialRequest,
            GetProfileKeyCredentialResponse,
            GetProfileKeyCredentialOut,
        >,
    > {
        let method = "/org.signal.chat.profile.ProfileAnonymous/GetProfileKeyCredential";
        let profile_key = zkgroup::profiles::ProfileKey::create([b'p'; zkgroup::PROFILE_KEY_LEN]);
        let commitment = profile_key.get_commitment(Aci::from(ACI_UUID));
        let server_secret_params =
            zkgroup::ServerSecretParams::generate([1; zkgroup::RANDOMNESS_LEN]);
        let server_params = server_secret_params.get_public_params();
        let request_context = server_params.create_profile_key_credential_request_context(
            [2; zkgroup::RANDOMNESS_LEN],
            Aci::from(ACI_UUID),
            profile_key,
        );
        let start_of_today = day_align(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("time goes forward")
                .as_secs(),
        );
        let zk_response = server_secret_params
            .issue_expiring_profile_key_credential(
                [3; zkgroup::RANDOMNESS_LEN],
                &request_context.get_request(),
                request_context.aci(),
                commitment,
                zkgroup::Timestamp::from_epoch_seconds(start_of_today + 2 * SECONDS_PER_DAY),
            )
            .expect("valid");
        let credential = server_params
            .receive_expiring_profile_key_credential(
                &request_context,
                &zk_response,
                SystemTime::now().into(),
            )
            .expect("valid");

        let case = |name: &str, response_grpc, response| GrpcTestCase {
            name: name.to_owned(),
            method: method.into(),
            request: GetProfileKeyCredentialArgs {
                profile_key_request_context: request_context.clone(),
                server_params: server_params.clone(),
            },
            request_grpc: GetProfileKeyCredentialRequest {
                account_identifier: Some(ServiceIdentifier {
                    identity_type: IdentityType::Aci.into(),
                    uuid: ACI_UUID.into_bytes().to_vec(),
                }),
                credential_request: zkgroup::serialize(&request_context.get_request()),
                credential_type: CredentialType::ExpiringProfileKey.into(),
                unidentified_access_key: profile_key.derive_access_key().to_vec(),
            },
            response_grpc,
            response,
        };

        vec![
            case(
                "success",
                GetProfileKeyCredentialResponse {
                    response: Some(GetProfileKeyCredentialResponseEnum::Result(
                        GetProfileKeyCredentialResult {
                            profile_key_credential: zkgroup::serialize(&zk_response),
                        },
                    )),
                },
                GetProfileKeyCredentialOut::Success(credential),
            ),
            case(
                "missing response",
                GetProfileKeyCredentialResponse { response: None },
                GetProfileKeyCredentialOut::UnexpectedError {
                    contains: "missing response",
                },
            ),
            case(
                "garbage credential",
                GetProfileKeyCredentialResponse {
                    response: Some(GetProfileKeyCredentialResponseEnum::Result(
                        GetProfileKeyCredentialResult {
                            profile_key_credential: vec![],
                        },
                    )),
                },
                GetProfileKeyCredentialOut::UnexpectedError {
                    contains: "Failed to deserialize",
                },
            ),
            case(
                "bad expiration",
                GetProfileKeyCredentialResponse {
                    response: Some(GetProfileKeyCredentialResponseEnum::Result(
                        GetProfileKeyCredentialResult {
                            profile_key_credential: zkgroup::serialize(
                                &server_secret_params
                                    .issue_expiring_profile_key_credential(
                                        [3; zkgroup::RANDOMNESS_LEN],
                                        &request_context.get_request(),
                                        request_context.aci(),
                                        commitment,
                                        zkgroup::Timestamp::from_epoch_seconds(
                                            start_of_today + 2 * SECONDS_PER_DAY + 1,
                                        ),
                                    )
                                    .expect("valid"),
                            ),
                        },
                    )),
                },
                GetProfileKeyCredentialOut::UnexpectedError {
                    contains: "Verification failure",
                },
            ),
            case(
                "not found",
                GetProfileKeyCredentialResponse {
                    response: Some(GetProfileKeyCredentialResponseEnum::NotFound(
                        errors::NotFound {},
                    )),
                },
                GetProfileKeyCredentialOut::ExplicitError(
                    ProfileKeyCredentialRequestError::ProfileNotFound,
                ),
            ),
            case(
                "auth failed",
                GetProfileKeyCredentialResponse {
                    response: Some(
                        GetProfileKeyCredentialResponseEnum::FailedUnidentifiedAuthorization(
                            errors::FailedUnidentifiedAuthorization {
                                description: "bad".to_owned(),
                            },
                        ),
                    ),
                },
                GetProfileKeyCredentialOut::ExplicitError(
                    ProfileKeyCredentialRequestError::AuthFailed,
                ),
            ),
        ]
    }

    pub use profile_utils::test_cases::*;
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use futures_util::FutureExt;
    use libsignal_core::{Aci, Pni};
    use libsignal_net_grpc::proto::chat::services;
    use test_case::test_matrix;

    use super::test_cases::*;
    use super::*;
    use crate::api::profiles::UnauthenticatedAccountExistenceApi;
    use crate::grpc::testutil::{
        GrpcOverrideRequestValidator, RequestValidator, err, ok, req, run_tests,
    };

    #[test_matrix([Aci::from(ACI_UUID).into(), Pni::from(PNI_UUID).into()], [false, true])]
    fn test_account_exists(service_id: ServiceId, found: bool) {
        let validator = GrpcOverrideRequestValidator {
            message: services::AccountsAnonymous::CheckAccountExistence.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.account.AccountsAnonymous/CheckAccountExistence",
                    CheckAccountExistenceRequest {
                        service_identifier: Some(service_id.into()),
                    },
                ),
                response: ok(CheckAccountExistenceResponse {
                    account_exists: found,
                }),
            },
        };
        let result = Unauth(&validator)
            .account_exists(service_id)
            .now_or_never()
            .expect("sync")
            .expect("success");
        assert_eq!(result, found);
    }

    #[test]
    fn test_account_exists_invalid() {
        let validator = GrpcOverrideRequestValidator {
            message: services::AccountsAnonymous::CheckAccountExistence.into(),
            validator: RequestValidator {
                expected: req(
                    "/org.signal.chat.account.AccountsAnonymous/CheckAccountExistence",
                    CheckAccountExistenceRequest {
                        service_identifier: Some(Aci::from(ACI_UUID).into()),
                    },
                ),
                response: err(tonic::Code::DeadlineExceeded),
            },
        };
        let result = Unauth(&validator)
            .account_exists(Aci::from(ACI_UUID).into())
            .now_or_never()
            .expect("sync")
            .expect_err("should fail");
        assert_matches!(result, RequestError::Timeout);
    }

    #[test]
    fn test_get_profile_key_credential() {
        run_tests(
            test_cases::get_profile_key_credential_test_cases(),
            |chat: Unauth<_>,
             GetProfileKeyCredentialArgs {
                 profile_key_request_context,
                 server_params,
             }| async move {
                chat.get_profile_key_credential(profile_key_request_context, &server_params)
                    .await
            },
            |expected, actual| match expected {
                GetProfileKeyCredentialOut::Success(expected_credential) => assert_eq!(
                    zkgroup::serialize(&expected_credential),
                    zkgroup::serialize(&actual.expect("success"))
                ),
                GetProfileKeyCredentialOut::UnexpectedError { contains } => {
                    let Err(err) = actual else {
                        panic!("should have failed");
                    };
                    assert_matches!(
                        err,
                        RequestError::Unexpected { log_safe }
                        if log_safe.contains(contains)
                    );
                }
                GetProfileKeyCredentialOut::ExplicitError(expected_err) => {
                    let Err(err) = actual else {
                        panic!("should have failed");
                    };
                    assert_eq!(
                        expected_err,
                        assert_matches!(err, RequestError::Other(e) => e)
                    );
                }
            },
        );
    }

    #[test]
    fn test_cdn_url() {
        for (url, success) in [
            ("https://cdn.signal.org/profiles/asdf", true),
            ("xhttps://cdn.signal.org/profiles/asdf", false),
            ("https://cdn2.signal.org/profiles/asdf", true),
            ("https://cdn3.signal.org/profiles/asdf", true),
            ("https://cdn3.signal.org/profiles/../asdf", true),
            ("https://cdn3.signal.or/profiles/asdf", false),
            ("https://example.com/profiles/asdf", false),
            ("ftp://example.com/profiles/asdf", false),
            ("gopher://example.com/profiles/asdf", false),
            ("https://cdn.signal.org.not-signal.example.com/asdf", false),
        ] {
            let out = CdnUrl::try_from(url.to_string());
            if success {
                assert_eq!(out.expect("success").as_ref(), url);
            } else {
                out.expect_err("bad url");
            }
        }
    }

    #[test]
    fn cdn_url_prefixes_have_trailing_slashes() {
        for prefix in CdnUrl::VALID_PREFIXES {
            assert!(prefix.ends_with('/'));
        }
    }

    #[test]
    fn test_get_profile() {
        run_tests(
            get_profile_test_cases(),
            |chat: Auth<_>,
             GetProfileArgs {
                 aci,
                 profile_key,
                 etag,
             }| async move { chat.get_profile(aci, &profile_key, etag).await },
            |expected, actual| match expected {
                GetProfileOut::Success(fetched_profile) => {
                    assert_eq!(actual.expect("success"), fetched_profile)
                }
                GetProfileOut::Failure(err) => match actual.expect_err("failure") {
                    RequestError::Other(actual_err) => assert_eq!(err, actual_err),
                    e => panic!("Expected RequestError::Other, not {e:?}"),
                },
            },
        );
    }

    #[test]
    fn test_set_profile() {
        run_tests(
            set_profile_test_cases(),
            |chat: Auth<_>,
             SetProfileArgs {
                 rng_seed,
                 aci,
                 profile_key,
                 profile,
                 expected_current_data_hash,
                 expected_current_profile_key_version,
             }| async move {
                chat.set_profile(
                    &mut seeded_rng(rng_seed),
                    aci,
                    &profile_key,
                    profile,
                    expected_current_data_hash,
                    expected_current_profile_key_version.as_ref(),
                )
                .await
            },
            |expected, actual| match expected {
                SetProfileOut::Success(hash) => assert_eq!(actual.expect("success"), hash),
                SetProfileOut::Failure(err) => match actual.expect_err("failure") {
                    RequestError::Other(actual_err) => assert_eq!(err, actual_err),
                    e => panic!("Expected RequestError::Other, not {e:?}"),
                },
            },
        );
    }
}
