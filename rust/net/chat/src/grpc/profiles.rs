//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::str::FromStr;
use std::time::SystemTime;

use async_trait::async_trait;
use displaydoc::Display;
use libsignal_core::{Aci, LogSafeDisplay, ServiceId};
use libsignal_net_grpc::proto::chat::account::accounts_anonymous_client::AccountsAnonymousClient;
use libsignal_net_grpc::proto::chat::account::{
    CheckAccountExistenceRequest, CheckAccountExistenceResponse,
};
use libsignal_net_grpc::proto::chat::errors::{
    self, FailedPrecondition, FailedZkAuthentication, NotFound,
};
use libsignal_net_grpc::proto::chat::profile::delete_avatar_response::Response as DeleteAvatarResponseEnum;
use libsignal_net_grpc::proto::chat::profile::extend_avatar_ttl_response::Response as ExtendAvatarResponseTtlEnum;
use libsignal_net_grpc::proto::chat::profile::get_avatar_credential_response::Response as GetAvatarCredentialResponseEnum;
use libsignal_net_grpc::proto::chat::profile::get_avatar_upload_form_response::Response as GetAvatarUploadFormResponseEnum;
use libsignal_net_grpc::proto::chat::profile::get_profile_key_credential_response::Response as GetProfileKeyCredentialResponseEnum;
use libsignal_net_grpc::proto::chat::profile::get_profile_response::Response as GetProfileResponseEnum;
use libsignal_net_grpc::proto::chat::profile::profile_anonymous_client::ProfileAnonymousClient;
use libsignal_net_grpc::proto::chat::profile::profile_client::ProfileClient;
use libsignal_net_grpc::proto::chat::profile::set_profile_response::Response as GrpcSetProfileResponse;
use libsignal_net_grpc::proto::chat::profile::{
    CredentialType, DeleteAvatarRequest, ExpectedVersionConflict, ExtendAvatarTtlRequest,
    GetAvatarCredentialRequest, GetAvatarUploadFormRequest, GetProfileAnonymousRequest,
    GetProfileKeyCredentialRequest, GetProfileKeyCredentialResponse, GetProfileKeyCredentialResult,
    GetProfileRequest, PaymentsForbiddenInRegion, SetProfileRequest, SetProfileResult,
    SetProfileV1Request, SetV1AvatarRequest, get_profile_anonymous_request,
    get_profile_anonymous_response,
};
use libsignal_protocol::IdentityKey;
use rand::{CryptoRng, Rng};
use strum::VariantArray;
use zkgroup::avatars::{
    AvatarUploadCredential, AvatarUploadCredentialPresentation,
    AvatarUploadCredentialRequestContext,
};
use zkgroup::generic_server_params::GenericServerPublicParams;
use zkgroup::groups::GroupSendFullToken;
use zkgroup::profiles::{ProfileKey, ProfileKeyVersion};
use zkgroup::zk_credential_key::ZkCredentialKeyPair;
use zkgroup::{PROFILE_KEY_VERSION_LEN, ProfileKeyBytes, ZkGroupVerificationFailure};

use crate::api::profiles::ProfileKeyCredentialRequestError;
use crate::api::{Auth, RequestError, S3UploadForm, Unauth};
use crate::grpc::accounts::ZkCredentialKeyRotationId;
use crate::grpc::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::impl_debug_from_display;
use crate::logging::Redact;

mod profile_utils;

pub type BadgeId = String;
pub type PaymentAddress = Vec<u8>;
pub type ProfileDataHash = [u8; 32];
pub const PROFILE_ETAG_LEN: usize = 10;
pub type ProfileEtag = [u8; PROFILE_ETAG_LEN];
pub type CdnUrl = String;

/// The provided AvatarCdnUrlValidationConfig ({config:?}) was invalid.
#[derive(Debug, Display, Clone)]
pub struct InvalidAvatarCdnUrlValidationConfig {
    pub config: AvatarCdnUrlValidationConfig,
}
impl LogSafeDisplay for InvalidAvatarCdnUrlValidationConfig where
    AvatarCdnUrlValidationConfig: LogSafeDisplay
{
}

#[derive(Debug, Clone)]
pub struct AvatarCdnUrlValidationConfig {
    /// URL prefixes must:
    /// 1. Start with `http://` or `https://`
    /// 2. end with a `/`
    valid_url_prefixes: Vec<String>,
}
impl AvatarCdnUrlValidationConfig {
    pub fn new(
        valid_url_prefixes: Vec<String>,
    ) -> Result<Self, InvalidAvatarCdnUrlValidationConfig> {
        let config = Self { valid_url_prefixes };
        for prefix in config.valid_url_prefixes.iter() {
            if !prefix.ends_with('/')
                || (!prefix.starts_with("http://") && !prefix.starts_with("https://"))
            {
                return Err(InvalidAvatarCdnUrlValidationConfig { config });
            }
        }
        Ok(config)
    }
    pub fn valid_url_prefixes(&self) -> &[String] {
        &self.valid_url_prefixes
    }
    pub fn validate_url(&self, url: &str) -> bool {
        if !url.is_ascii() {
            log::warn!("Avatar URL isn't ASCII.");
            return false;
        }
        if !self
            .valid_url_prefixes()
            .iter()
            .any(|prefix| url.starts_with(prefix))
        {
            log::warn!(
                "Avatar URL didn't start with any valid prefix ({})",
                self.log_safe_display()
            );
            return false;
        }
        if url.contains("../") || url.contains("/..") {
            log::warn!("Avatar URL contains '../' or '/..'");
            return false;
        }
        if http::Uri::from_str(url).is_err() {
            log::warn!("Avatar URL isn't even a valid URL");
            return false;
        }
        true
    }
}
impl std::fmt::Display for AvatarCdnUrlValidationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
/// This structure is configuration and, therefore, log-safe
impl LogSafeDisplay for AvatarCdnUrlValidationConfig {}

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Profile {
    /// Optional (can be empty); max-length is 128 bytes
    pub given_name: String,
    /// Optional (can be empty); max-length is 128 bytes
    pub family_name: String,
    /// Optional (can be empty); max-length is 512 bytes
    pub about: String,
    /// Optional (can be empty); max-length is 32 bytes
    pub about_emoji: String,
    /// If provided, it must be the full URL to the avatar.
    ///
    /// The URL must point to a Signal CDN server. (This will be validated on outgoing and incoming
    /// profiles.)
    pub avatar: Option<CdnUrl>,
    // The following fields are conceptually part of the user's profile, but live outside of the
    // encrypted v2 PlaintextProfileData
    /// The `None`-ness of this value is respected for _incoming_ profiles.
    /// It is an error to pass `None` for outgoing profiles (i.e. when `set_profile()` is called)
    pub phone_number_sharing: Option<bool>,
    pub payment_address: Option<PaymentAddress>,
    pub badge_ids: Vec<BadgeId>,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            given_name: Default::default(),
            family_name: Default::default(),
            about: Default::default(),
            about_emoji: Default::default(),
            avatar: Default::default(),
            phone_number_sharing: Some(false),
            payment_address: Default::default(),
            badge_ids: Default::default(),
        }
    }
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
    /// The avatar URL is invalid
    AvatarUrlInvalid,
}
impl LogSafeDisplay for ProfileValidationError {}

impl Profile {
    /// Validate that a profile meets the validation rules.
    ///
    /// If there are any validation errors, they will be added to `validation_errors`.
    /// Any invalid fields will be blanked.
    fn sanitize(
        &mut self,
        cdn_config: &AvatarCdnUrlValidationConfig,
        validation_errors: &mut Vec<ProfileValidationError>,
    ) {
        use ProfileFieldWithMaxLength::*;
        for (field, string) in [
            (GivenName, &mut self.given_name),
            (FamilyName, &mut self.family_name),
            (About, &mut self.about),
            (AboutEmoji, &mut self.about_emoji),
        ] {
            if string.len() > field.max_length() {
                validation_errors.push(ProfileValidationError::FieldTooLong {
                    field,
                    len: string.len(),
                    max_len: field.max_length(),
                });
                string.clear();
            }
        }
        if let Some(payment_address) = self.payment_address.as_ref()
            && payment_address.len() > PaymentAddress.max_length()
        {
            validation_errors.push(ProfileValidationError::FieldTooLong {
                field: PaymentAddress,
                len: payment_address.len(),
                max_len: PaymentAddress.max_length(),
            });
            self.payment_address = None;
        }
        if let Some(avatar) = self.avatar.as_ref() {
            let avatar_len = avatar.len();
            if !cdn_config.validate_url(avatar) {
                validation_errors.push(ProfileValidationError::AvatarUrlInvalid);
                self.avatar = None;
            }
            if avatar_len > Avatar.max_length() {
                validation_errors.push(ProfileValidationError::FieldTooLong {
                    field: Avatar,
                    len: avatar_len,
                    max_len: Avatar.max_length(),
                });
                self.avatar = None;
            }
        }
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
    /// This should only be `None` if `unrestricted_unidentified_access` is `true`
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
    /// Failed to protobuf decode the plaintext profile v2 data
    ProfileV2InvalidProtobuf,
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
    /// Profile v2 encrypted data of size {len}, is too small to have a tag.
    ProfileV2DataTooSmallForTag { len: usize },
    /// Profile v2 encrypted data of size {len}, is too small to have a nonce.
    ProfileV2DataTooSmallForNonce { len: usize },
    /// Profile v2 encrypted data had mismatched tag
    ProfileV2DataMismatchedTag,
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
impl LogSafeDisplay for ProfileDecodeError where ProfileValidationError: LogSafeDisplay {}

#[derive(Debug, Clone, Display, PartialEq, Eq)]
pub enum AuthGetProfileError {
    /// A profile could not be found
    ProfileNotFound,
    /// The profile could not be decoded: {log_safe}
    ProfileDecodeError { log_safe: String },
}

#[derive(Debug, Clone, Display, PartialEq, Eq)]
pub enum UnauthGetProfileError {
    /// A profile could not be found
    ProfileNotFound,
    /// The profile could not be decoded: {log_safe}
    ProfileDecodeError { log_safe: String },
    /// Authorizaton failed
    FailedUnidentifiedAuthorization,
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
    /// `phone_number_sharing` being `None` is allowed for backwards compatiblity on _incoming_
    /// profiles, but it's disallowed on _outgoing_ profiles.
    IndeterminatePhoneNumberSharingDisallowedOnOutgoingProfiles,
}
// We want to ensure that any current_profile_version doesn't get printed.
impl_debug_from_display!(SetProfileError);

impl std::fmt::Display for Redact<SetV1AvatarRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(SetV1AvatarRequest {
            version,
            commitment,
        }) = self;
        f.debug_struct("SetV1AvatarRequest")
            .field("version.len()", &version.len())
            .field("commitment.len()", &commitment.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<GetAvatarCredentialRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(GetAvatarCredentialRequest {
            avatar_credential_request,
        }) = self;
        f.debug_struct("GetAvatarCredentialRequest")
            .field(
                "avatar_credential_request.len()",
                &avatar_credential_request.len(),
            )
            .finish()
    }
}

/// The account is missing a ZK Credential key
/// The account must've called `set_zk_credential_key()` before calling this.
#[derive(Display, Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountMissingZkCredentialKey;

impl<T: GrpcServiceProvider> Auth<T> {
    /// Returns an anonymous credential that may be presented with avatar operations in
    /// `UnauthProfilesService`
    ///
    /// This method will error out if the account doesn't have a ZK credential key set
    pub async fn get_avatar_credential(
        &self,
        aci: Aci,
        key_pair: &ZkCredentialKeyPair,
        rotation_id: ZkCredentialKeyRotationId,
        server_public_params: &GenericServerPublicParams,
        current_time: zkgroup::Timestamp,
        rng: &mut (dyn CryptoRng + Send),
    ) -> Result<AvatarUploadCredential, RequestError<AccountMissingZkCredentialKey>> {
        let ctx = AvatarUploadCredentialRequestContext::new(
            aci,
            key_pair,
            rotation_id.try_into().expect("Rotation ID must be >= 0"),
            rng.random(),
        );
        let request = GetAvatarCredentialRequest {
            avatar_credential_request: zkgroup::serialize(&ctx.get_request()),
        };
        let log_safe_description = Redact(&request).to_string();
        let mut profiles_service = ProfileClient::new(self.0.service());
        match log_and_send(Self::LOG_TAG, &log_safe_description, || {
            profiles_service.get_avatar_credential(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".into(),
        })? {
            GetAvatarCredentialResponseEnum::AvatarCredential(credential) => ctx
                .receive(
                    zkgroup::deserialize(&credential).map_err(|_| RequestError::Unexpected {
                        // We don't log the error, since it only describes the type name
                        log_safe: "Unable to deserialize AvatarUploadCredentialResponse".into(),
                    })?,
                    server_public_params,
                    current_time,
                )
                .map_err(|ZkGroupVerificationFailure| RequestError::Unexpected {
                    log_safe: "Unable to receive AvatarUploadCredential".into(),
                }),
            GetAvatarCredentialResponseEnum::MissingZkCredentialKey(FailedPrecondition {
                description: _,
            }) => Err(RequestError::Other(AccountMissingZkCredentialKey)),
        }
    }

    /// Returns a form to upload a legacy (v1) avatar.
    pub async fn get_avatar_upload_form_legacy(
        &self,
        aci: Aci,
        profile_key: &ProfileKey,
    ) -> Result<S3UploadForm, RequestError<Infallible>> {
        let version = profile_key.get_profile_key_version(aci);
        let commitment = profile_key.get_commitment(aci);
        let request = SetV1AvatarRequest {
            version: hex::encode(version.bytes),
            commitment: zkgroup::serialize(&commitment),
        };
        let log_safe_description = Redact(&request).to_string();
        let mut profiles_service = ProfileClient::new(self.0.service());
        log_and_send(Self::LOG_TAG, &log_safe_description, || {
            profiles_service.set_v1_avatar(request)
        })
        .await?
        .into_inner()
        .form
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing S3 form".into(),
        })?
        .try_into()
    }
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
        avatar_cdn_config: &AvatarCdnUrlValidationConfig,
    ) -> Result<Option<FetchedProfile>, RequestError<AuthGetProfileError>> {
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
            GetProfileResponseEnum::Profile(profile_result) => profile_utils::v2::decrypt_profile(
                aci,
                profile_key,
                profile_result,
                avatar_cdn_config,
            )
            .map(Some)
            .map_err(|e| match e {
                profile_utils::Error::ProfileDecodeError(e) => {
                    RequestError::Other(AuthGetProfileError::ProfileDecodeError {
                        log_safe: e.log_safe_display().to_string(),
                    })
                }
                profile_utils::Error::Unexpected { log_safe } => {
                    RequestError::Unexpected { log_safe }
                }
            }),
            // We only care that the EtagMatched protobuf oneof variant is selected; we don't care
            // about its value. In practice, the server will set it to true.
            GetProfileResponseEnum::EtagMatched(true | false) => Ok(None),
            GetProfileResponseEnum::NotFound(errors::NotFound {}) => {
                Err(RequestError::Other(AuthGetProfileError::ProfileNotFound))
            }
            GetProfileResponseEnum::LegacyProfile(legacy_profile_result) => {
                profile_utils::v1::decrypt_profile(
                    profile_key,
                    &legacy_profile_result,
                    avatar_cdn_config,
                )
                .map(Some)
                .map_err(|e| match e {
                    profile_utils::Error::ProfileDecodeError(e) => {
                        RequestError::Other(AuthGetProfileError::ProfileDecodeError {
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
        rng: &mut (dyn CryptoRng + Send),
        aci: Aci,
        profile_key: &ProfileKey,
        mut profile: Profile,
        expected_current_data_hash: Option<ProfileDataHash>,
        expected_current_profile_key_version: Option<&ProfileKeyVersion>,
        avatar_cdn_config: &AvatarCdnUrlValidationConfig,
    ) -> Result<ProfileDataHash, RequestError<SetProfileError>> {
        let mut validation_errors = Vec::new();
        profile.sanitize(avatar_cdn_config, &mut validation_errors);
        if let Some(e) = validation_errors.first() {
            return Err(RequestError::Other(SetProfileError::InvalidProfile(*e)));
        }
        if profile.phone_number_sharing.is_none() {
            return Err(RequestError::Other(
                SetProfileError::IndeterminatePhoneNumberSharingDisallowedOnOutgoingProfiles,
            ));
        }
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

#[derive(Clone)]
pub enum UnauthProfileAuthorization {
    /// An unidentified access key
    AccessKey([u8; 16]),
    GroupSend(GroupSendFullToken),
}

impl std::fmt::Display for Redact<GetProfileAnonymousRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(GetProfileAnonymousRequest {
            request,
            authentication,
        }) = self;
        f.debug_struct("GetProfileAnonymousRequest")
            .field("request", &request.as_ref().map(Redact))
            .field(
                "authentication",
                &match authentication {
                    Some(get_profile_anonymous_request::Authentication::UnidentifiedAccessKey(
                        _,
                    )) => "UnidentifiedAccessKey",
                    Some(get_profile_anonymous_request::Authentication::GroupSendToken(_)) => {
                        "GroupSendToken"
                    }
                    None => todo!(),
                },
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Display)]
/// Invalid AvatarUploadCredentialPresentation
pub struct InvalidAvatarUploadCredentialPresentation;

impl std::fmt::Display for Redact<ExtendAvatarTtlRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(ExtendAvatarTtlRequest {
            avatar_credential_presentation,
        }) = self;
        f.debug_struct("ExtendAvatarTtlRequest")
            .field(
                "avatar_credential_presentation.len()",
                &avatar_credential_presentation.len(),
            )
            .finish()
    }
}

impl std::fmt::Display for Redact<DeleteAvatarRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(DeleteAvatarRequest {
            avatar_credential_presentation,
        }) = self;
        f.debug_struct("DeleteAvatarRequest")
            .field(
                "avatar_credential_presentation.len()",
                &avatar_credential_presentation.len(),
            )
            .finish()
    }
}

impl std::fmt::Display for Redact<GetAvatarUploadFormRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(GetAvatarUploadFormRequest {
            avatar_credential_presentation,
            upload_length,
        }) = self;
        f.debug_struct("GetAvatarUploadFormRequest")
            .field(
                "avatar_credential_presentation.len()",
                &avatar_credential_presentation.len(),
            )
            .field("upload_length", &upload_length)
            .finish()
    }
}
impl<T: GrpcServiceProvider> Unauth<T> {
    /// Returns a credential to upload a v2 avatar. After uploading the avatar, the client
    /// must call SetProfile with the new avatar URL in the encrypted `data`.
    ///
    /// Because avatars are uploaded anonymously, they have an expiration equal to the
    /// idle account expiration. Clients must periodically (recommended: every 90 days)
    /// call `extend_avatar_ttl()` to extend the TTl.
    ///
    /// NOTE: any existing avatar associated with this credential will be deleted immediately
    ///
    /// Clients should _not_ be uploading v2 avatars until after the v1->v2 avatar transition.
    ///
    /// Uploads will be limited to `upload_length` bytes. It must be in the range `[1, 10485760]`
    /// (10 MiB), else the server will reject the upload.
    pub async fn get_avatar_upload_form(
        &self,
        credential: &AvatarUploadCredentialPresentation,
        upload_length: i32,
    ) -> Result<S3UploadForm, RequestError<InvalidAvatarUploadCredentialPresentation>> {
        let mut service = ProfileAnonymousClient::new(self.0.service());
        let request = GetAvatarUploadFormRequest {
            avatar_credential_presentation: zkgroup::serialize(credential),
            upload_length: upload_length
                .try_into()
                .expect("upload_length is non-negative"),
        };
        let log_safe_description = Redact(&request).to_string();
        match log_and_send(Self::LOG_TAG, &log_safe_description, || {
            service.get_avatar_upload_form(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".into(),
        })? {
            GetAvatarUploadFormResponseEnum::AvatarUploadForm(s3_upload_form) => s3_upload_form
                .try_into()
                .map_err(|e: RequestError<Infallible>| e.with_other()),
            GetAvatarUploadFormResponseEnum::InvalidCredentialPresentation(
                FailedZkAuthentication { description: _ },
            ) => Err(RequestError::Other(
                InvalidAvatarUploadCredentialPresentation,
            )),
        }
    }

    /// Extend the TTL of a v2 avatar
    ///
    /// The server doesn't know which v2 avatars correspond to which Signal account. As a result,
    /// v2 avatars expire after a time. To keep an account's avatar from expiring, clients must
    /// call `extend_avatar_ttl()` on a regular basis (recommended: every 90 days).
    ///
    /// It is safe to keep calling this during the v1->v2 transition. v1 avatars will just be
    /// treated as "not found."
    ///
    /// Returns either the [`CdnUrl`] of the current v2 avtar, or `None`, if none is set.
    pub async fn extend_avatar_ttl(
        &self,
        credential: &AvatarUploadCredentialPresentation,
    ) -> Result<Option<CdnUrl>, RequestError<InvalidAvatarUploadCredentialPresentation>> {
        let mut service = ProfileAnonymousClient::new(self.0.service());
        let request = ExtendAvatarTtlRequest {
            avatar_credential_presentation: zkgroup::serialize(credential),
        };
        let log_safe_description = Redact(&request).to_string();
        match log_and_send(Self::LOG_TAG, &log_safe_description, || {
            service.extend_avatar_ttl(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".into(),
        })? {
            ExtendAvatarResponseTtlEnum::Url(url) => Ok(Some(url)),
            ExtendAvatarResponseTtlEnum::InvalidCredentialPresentation(
                FailedZkAuthentication { description },
            ) => {
                log::warn!(
                    "ExtendAvatarTtl failed due to invalid credential presentation: {description}"
                );
                Err(RequestError::Other(
                    InvalidAvatarUploadCredentialPresentation,
                ))
            }
            ExtendAvatarResponseTtlEnum::NotFound(NotFound {}) => Ok(None),
        }
    }

    /// Delete the account's avatar from the CDN.
    ///
    /// Clients must also call `set_profile()` to remove the avatar URL from the profile data.
    pub async fn delete_avatar(
        &self,
        credential: &AvatarUploadCredentialPresentation,
    ) -> Result<(), RequestError<InvalidAvatarUploadCredentialPresentation>> {
        let mut service = ProfileAnonymousClient::new(self.0.service());
        let request = DeleteAvatarRequest {
            avatar_credential_presentation: zkgroup::serialize(credential),
        };
        let log_safe_description = Redact(&request).to_string();
        match log_and_send(Self::LOG_TAG, &log_safe_description, || {
            service.delete_avatar(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".into(),
        })? {
            DeleteAvatarResponseEnum::Success(()) => Ok(()),
            DeleteAvatarResponseEnum::InvalidCredentialPresentation(FailedZkAuthentication {
                description: _,
            }) => Err(RequestError::Other(
                InvalidAvatarUploadCredentialPresentation,
            )),
        }
    }

    /// Retrieves profile data.
    ///
    /// If an `etag` is provided, and the profile etag remains unchanged, this returns `None` to
    /// indicate that the profile was already up-to-date.
    pub async fn get_profile(
        &self,
        aci: Aci,
        profile_key: &ProfileKey,
        auth: &UnauthProfileAuthorization,
        etag: Option<ProfileEtag>,
        avatar_cdn_config: &AvatarCdnUrlValidationConfig,
    ) -> Result<Option<FetchedProfile>, RequestError<UnauthGetProfileError>> {
        let version = profile_key.get_profile_key_version(aci);
        let request = GetProfileAnonymousRequest {
            request: Some(GetProfileRequest {
                account_identifier: Some(aci.into()),
                version: version.as_ref().to_vec(),
                etag: etag.map(|etag| etag.to_vec()).unwrap_or_default(),
            }),
            authentication: match auth {
                UnauthProfileAuthorization::AccessKey(uak) => Some(
                    get_profile_anonymous_request::Authentication::UnidentifiedAccessKey(
                        uak.to_vec(),
                    ),
                ),
                UnauthProfileAuthorization::GroupSend(group_send_token) => Some(
                    get_profile_anonymous_request::Authentication::GroupSendToken(
                        zkgroup::serialize(&group_send_token),
                    ),
                ),
            },
        };
        let log_safe_description = Redact(&request).to_string();
        let mut profiles_service = ProfileAnonymousClient::new(self.0.service());
        match log_and_send(Self::LOG_TAG, &log_safe_description, || {
            profiles_service.get_profile(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".into(),
        })? {
            get_profile_anonymous_response::Response::Profile(profile_result) => {
                profile_utils::v2::decrypt_profile(
                    aci,
                    profile_key,
                    profile_result,
                    avatar_cdn_config,
                )
                .map(Some)
                .map_err(|e| match e {
                    profile_utils::Error::ProfileDecodeError(e) => {
                        RequestError::Other(UnauthGetProfileError::ProfileDecodeError {
                            log_safe: e.log_safe_display().to_string(),
                        })
                    }
                    profile_utils::Error::Unexpected { log_safe } => {
                        RequestError::Unexpected { log_safe }
                    }
                })
            }
            get_profile_anonymous_response::Response::ProfileV1(legacy_profile_result) => {
                profile_utils::v1::decrypt_profile(
                    profile_key,
                    &legacy_profile_result,
                    avatar_cdn_config,
                )
                .map(Some)
                .map_err(|e| match e {
                    profile_utils::Error::ProfileDecodeError(e) => {
                        RequestError::Other(UnauthGetProfileError::ProfileDecodeError {
                            log_safe: e.log_safe_display().to_string(),
                        })
                    }
                    profile_utils::Error::Unexpected { log_safe } => {
                        RequestError::Unexpected { log_safe }
                    }
                })
            }
            get_profile_anonymous_response::Response::EtagMatched(true | false) => Ok(None),
            get_profile_anonymous_response::Response::NotFound(errors::NotFound {}) => {
                Err(RequestError::Other(UnauthGetProfileError::ProfileNotFound))
            }
            get_profile_anonymous_response::Response::FailedUnidentifiedAuthorization(
                _failed_unidentified_authorization,
            ) => Err(RequestError::Other(
                UnauthGetProfileError::FailedUnidentifiedAuthorization,
            )),
        }
    }

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
    use libsignal_net_grpc::proto::chat::profile::{
        DeleteAvatarResponse, ExtendAvatarTtlResponse, GetAvatarCredentialResponse,
        GetAvatarUploadFormResponse, SetV1AvatarResponse,
    };
    use uuid::{Uuid, uuid};
    use zkgroup::SECONDS_PER_DAY;
    use zkgroup::avatars::{
        AvatarUploadCredentialRequest, AvatarUploadCredentialRequestContext,
        AvatarUploadCredentialResponse,
    };
    use zkgroup::generic_server_params::GenericServerSecretParamsStandard;
    use zkgroup::zk_credential_key::ZkCredentialKeyPair;

    use super::*;
    use crate::grpc::GrpcTestCase;
    use crate::grpc::test_case_util::day_align;

    pub(crate) const ACI_UUID: Uuid = uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
    #[cfg(test)]
    pub(crate) const PNI_UUID: Uuid = uuid!("796abedb-ca4e-4f18-8803-1fde5b921f9f");

    pub struct GetAvatarCredentialArgs {
        pub aci: Aci,
        pub key_pair: ZkCredentialKeyPair,
        pub rotation_id: ZkCredentialKeyRotationId,
        pub server_public_params: GenericServerPublicParams,
        pub current_time: zkgroup::Timestamp,
    }
    /// `None` if the account is missing a zk credential key
    pub type GetAvatarCredentialOut = Option<AvatarUploadCredential>;
    pub fn get_avatar_credential_test_cases() -> Vec<
        GrpcTestCase<
            GetAvatarCredentialArgs,
            GetAvatarCredentialRequest,
            GetAvatarCredentialResponse,
            GetAvatarCredentialOut,
        >,
    > {
        let method = "/org.signal.chat.profile.Profile/GetAvatarCredential";
        let TestAvatarUploadCredential {
            aci,
            key_pair,
            rotation_id,
            current_time,
            server_public_params,
            request,
            response,
            credential,
            presentation: _,
        } = Default::default();
        vec![
            GrpcTestCase {
                name: "success".into(),
                method: method.into(),
                request: GetAvatarCredentialArgs {
                    aci,
                    key_pair: key_pair.clone(),
                    rotation_id,
                    server_public_params: server_public_params.clone(),
                    current_time,
                },
                request_grpc: GetAvatarCredentialRequest {
                    avatar_credential_request: zkgroup::serialize(&request),
                },
                response_grpc: GetAvatarCredentialResponse {
                    response: Some(GetAvatarCredentialResponseEnum::AvatarCredential(
                        zkgroup::serialize(&response),
                    )),
                },
                response: Some(credential),
            },
            GrpcTestCase {
                name: "failure".into(),
                method: method.into(),
                request: GetAvatarCredentialArgs {
                    aci,
                    key_pair,
                    rotation_id,
                    server_public_params,
                    current_time,
                },
                request_grpc: GetAvatarCredentialRequest {
                    avatar_credential_request: zkgroup::serialize(&request),
                },
                response_grpc: GetAvatarCredentialResponse {
                    response: Some(GetAvatarCredentialResponseEnum::MissingZkCredentialKey(
                        Default::default(),
                    )),
                },
                response: None,
            },
        ]
    }

    #[derive(Clone)]
    pub struct GetAvatarUploadFormLegacyArgs {
        pub aci: Aci,
        pub profile_key: ProfileKey,
    }
    pub type GetAvatarUploadFormLegacyOut = S3UploadForm;

    pub fn get_avatar_upload_form_legacy_test_cases() -> Vec<
        GrpcTestCase<
            GetAvatarUploadFormLegacyArgs,
            SetV1AvatarRequest,
            SetV1AvatarResponse,
            GetAvatarUploadFormLegacyOut,
        >,
    > {
        let method = "/org.signal.chat.profile.Profile/SetV1Avatar";
        let aci = Aci::from_uuid_bytes([0x1; 16]);
        let profile_key = ProfileKey { bytes: [0x2; _] };
        vec![GrpcTestCase {
            name: "success".into(),
            method: method.into(),
            request: GetAvatarUploadFormLegacyArgs { aci, profile_key },
            request_grpc: SetV1AvatarRequest {
                version: String::from_utf8(zkgroup::serialize(
                    &profile_key.get_profile_key_version(aci),
                ))
                .expect("valid utf-8"),
                commitment: zkgroup::serialize(&profile_key.get_commitment(aci)),
            },
            response_grpc: SetV1AvatarResponse {
                form: Some(libsignal_net_grpc::proto::chat::common::S3UploadForm {
                    key: "key".into(),
                    credential: "credential".into(),
                    acl: "acl".into(),
                    algorithm: "Floyd–Warshall".into(),
                    date: "today".into(),
                    policy: "policy".into(),
                    signature: "abcd".into(),
                }),
            },
            response: S3UploadForm {
                key: "key".into(),
                credential: "credential".into(),
                acl: "acl".into(),
                algorithm: "Floyd–Warshall".into(),
                date: "today".into(),
                policy: "policy".into(),
                signature: "abcd".into(),
            },
        }]
    }

    #[derive(Clone)]
    pub struct GetAvatarUploadFormArgs {
        pub credential: AvatarUploadCredentialPresentation,
        pub upload_length: i32,
    }
    #[derive(Clone, Debug)]
    pub enum GetAvatarUploadFormOut {
        Success(S3UploadForm),
        InvalidCredential,
    }

    pub fn get_avatar_upload_form_test_cases() -> Vec<
        GrpcTestCase<
            GetAvatarUploadFormArgs,
            GetAvatarUploadFormRequest,
            GetAvatarUploadFormResponse,
            GetAvatarUploadFormOut,
        >,
    > {
        let method = "/org.signal.chat.profile.ProfileAnonymous/GetAvatarUploadForm";
        let presentation = TestAvatarUploadCredential::default().presentation;
        vec![
            GrpcTestCase {
                name: "success".into(),
                method: method.into(),
                request: GetAvatarUploadFormArgs {
                    credential: presentation.clone(),
                    upload_length: 1234,
                },
                request_grpc: GetAvatarUploadFormRequest {
                    avatar_credential_presentation: zkgroup::serialize(&presentation),
                    upload_length: 1234,
                },
                response_grpc: GetAvatarUploadFormResponse {
                    response: Some(GetAvatarUploadFormResponseEnum::AvatarUploadForm(
                        libsignal_net_grpc::proto::chat::common::S3UploadForm {
                            key: "key".into(),
                            credential: "credential".into(),
                            acl: "acl".into(),
                            algorithm: "Floyd–Warshall".into(),
                            date: "today".into(),
                            policy: "policy".into(),
                            signature: "abcd".into(),
                        },
                    )),
                },
                response: GetAvatarUploadFormOut::Success(S3UploadForm {
                    key: "key".into(),
                    credential: "credential".into(),
                    acl: "acl".into(),
                    algorithm: "Floyd–Warshall".into(),
                    date: "today".into(),
                    policy: "policy".into(),
                    signature: "abcd".into(),
                }),
            },
            GrpcTestCase {
                name: "zk failure".into(),
                method: method.into(),
                request: GetAvatarUploadFormArgs {
                    credential: presentation.clone(),
                    upload_length: 1234,
                },
                request_grpc: GetAvatarUploadFormRequest {
                    avatar_credential_presentation: zkgroup::serialize(&presentation),
                    upload_length: 1234,
                },
                response_grpc: GetAvatarUploadFormResponse {
                    response: Some(
                        GetAvatarUploadFormResponseEnum::InvalidCredentialPresentation(
                            Default::default(),
                        ),
                    ),
                },
                response: GetAvatarUploadFormOut::InvalidCredential,
            },
        ]
    }

    pub type ExtendAvatarTtlArgs = AvatarUploadCredentialPresentation;
    #[derive(Clone, Debug)]
    pub enum ExtendAvatarTtlOut {
        Found(CdnUrl),
        NotFound,
        InvalidCredentials,
    }

    pub type DeleteAvatarArgs = AvatarUploadCredentialPresentation;
    /// `true` if success. `false` if the credentials were invalid
    pub type DeleteAvatarOut = bool;

    pub(crate) struct TestAvatarUploadCredential {
        aci: Aci,
        key_pair: ZkCredentialKeyPair,
        rotation_id: ZkCredentialKeyRotationId,
        current_time: zkgroup::Timestamp,
        server_public_params: GenericServerPublicParams,
        request: AvatarUploadCredentialRequest,
        response: AvatarUploadCredentialResponse,
        credential: AvatarUploadCredential,
        presentation: AvatarUploadCredentialPresentation,
    }
    impl Default for TestAvatarUploadCredential {
        fn default() -> Self {
            let server_params = GenericServerSecretParamsStandard::generate([0x0; _]);
            let aci = Aci::from_uuid_bytes([0x1; _]);
            let key_pair = ZkCredentialKeyPair::generate([0x2; _]);
            let rotation_id = 0x3;
            let request_context = AvatarUploadCredentialRequestContext::new(
                aci,
                &key_pair,
                rotation_id,
                profile_utils::test_cases::seeded_rng(0).random(),
            );
            let current_time = zkgroup::Timestamp::from_epoch_seconds(SECONDS_PER_DAY * 100);
            let server_public_params = server_params.get_public_params().into();
            let request = request_context.get_request();
            let response = request
                .issue(
                    aci,
                    &key_pair.public_key(),
                    rotation_id,
                    current_time,
                    &server_params.into(),
                    [0x6; _],
                )
                .expect("can generate response");
            let credential = request_context
                .receive(response.clone(), &server_public_params, current_time)
                .expect("can receive credential");
            let presentation = credential.present(&server_public_params, [0x7; _]);
            Self {
                aci,
                key_pair,
                rotation_id: rotation_id.try_into().expect("rotation id in range"),
                current_time,
                server_public_params,
                request,
                response,
                credential,
                presentation,
            }
        }
    }

    pub fn delete_avatar_test_cases() -> Vec<
        GrpcTestCase<DeleteAvatarArgs, DeleteAvatarRequest, DeleteAvatarResponse, DeleteAvatarOut>,
    > {
        let method = "/org.signal.chat.profile.ProfileAnonymous/DeleteAvatar";
        let presentation = TestAvatarUploadCredential::default().presentation;
        vec![
            GrpcTestCase {
                name: "success".into(),
                method: method.into(),
                request: presentation.clone(),
                request_grpc: DeleteAvatarRequest {
                    avatar_credential_presentation: zkgroup::serialize(&presentation),
                },
                response_grpc: DeleteAvatarResponse {
                    response: Some(DeleteAvatarResponseEnum::Success(())),
                },
                response: true,
            },
            GrpcTestCase {
                name: "bad credential".into(),
                method: method.into(),
                request: presentation.clone(),
                request_grpc: DeleteAvatarRequest {
                    avatar_credential_presentation: zkgroup::serialize(&presentation),
                },
                response_grpc: DeleteAvatarResponse {
                    response: Some(DeleteAvatarResponseEnum::InvalidCredentialPresentation(
                        Default::default(),
                    )),
                },
                response: false,
            },
        ]
    }

    pub fn extend_avatar_ttl_test_cases() -> Vec<
        GrpcTestCase<
            ExtendAvatarTtlArgs,
            ExtendAvatarTtlRequest,
            ExtendAvatarTtlResponse,
            ExtendAvatarTtlOut,
        >,
    > {
        let method = "/org.signal.chat.profile.ProfileAnonymous/ExtendAvatarTTL";
        let presentation = TestAvatarUploadCredential::default().presentation;
        vec![
            GrpcTestCase {
                name: "found".into(),
                method: method.into(),
                request: presentation.clone(),
                request_grpc: ExtendAvatarTtlRequest {
                    avatar_credential_presentation: zkgroup::serialize(&presentation),
                },
                response_grpc: ExtendAvatarTtlResponse {
                    response: Some(ExtendAvatarResponseTtlEnum::Url(
                        "https://cdn.signal.org/asdf".into(),
                    )),
                },
                response: ExtendAvatarTtlOut::Found("https://cdn.signal.org/asdf".to_owned()),
            },
            GrpcTestCase {
                name: "not found".into(),
                method: method.into(),
                request: presentation.clone(),
                request_grpc: ExtendAvatarTtlRequest {
                    avatar_credential_presentation: zkgroup::serialize(&presentation),
                },
                response_grpc: ExtendAvatarTtlResponse {
                    response: Some(ExtendAvatarResponseTtlEnum::NotFound(Default::default())),
                },
                response: ExtendAvatarTtlOut::NotFound,
            },
            GrpcTestCase {
                name: "bad credential".into(),
                method: method.into(),
                request: presentation.clone(),
                request_grpc: ExtendAvatarTtlRequest {
                    avatar_credential_presentation: zkgroup::serialize(&presentation),
                },
                response_grpc: ExtendAvatarTtlResponse {
                    response: Some(ExtendAvatarResponseTtlEnum::InvalidCredentialPresentation(
                        Default::default(),
                    )),
                },
                response: ExtendAvatarTtlOut::InvalidCredentials,
            },
        ]
    }

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
    fn test_get_profile() {
        run_tests(
            get_profile_test_cases(),
            |chat: Auth<_>,
             GetProfileArgs {
                 aci,
                 profile_key,
                 etag,
                 avatar_cdn_config,
             }| async move {
                chat.get_profile(aci, &profile_key, etag, &avatar_cdn_config)
                    .await
            },
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
    fn test_get_profile_unauth() {
        run_tests(
            get_profile_unauth_test_cases(),
            |chat: Unauth<_>,
             UnauthGetProfileArgs {
                 inner:
                     GetProfileArgs {
                         aci,
                         profile_key,
                         etag,
                         avatar_cdn_config,
                     },
                 auth,
             }| async move {
                chat.get_profile(aci, &profile_key, &auth, etag, &avatar_cdn_config)
                    .await
            },
            |expected, actual| match expected {
                UnauthGetProfileOut::Success(fetched_profile) => {
                    assert_eq!(actual.expect("success"), fetched_profile)
                }
                UnauthGetProfileOut::Failure(err) => match actual.expect_err("failure") {
                    RequestError::Other(actual_err) => assert_eq!(err, actual_err),
                    e => panic!("Expected RequestError::Other, not {e:?}"),
                },
            },
        );
    }

    #[test]
    fn test_set_profile() {
        run_tests(
            set_profile_test_cases()
                .into_iter()
                .chain(set_profile_validation_test_cases()),
            |chat: Auth<_>,
             SetProfileArgs {
                 rng_seed,
                 aci,
                 profile_key,
                 profile,
                 expected_current_data_hash,
                 expected_current_profile_key_version,
                 avatar_cdn_config,
             }| async move {
                chat.set_profile(
                    &mut seeded_rng(rng_seed as u64),
                    aci,
                    &profile_key,
                    profile,
                    expected_current_data_hash,
                    expected_current_profile_key_version.as_ref(),
                    &avatar_cdn_config,
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

    #[test]
    fn test_extend_avatar_ttl() {
        run_tests(
            extend_avatar_ttl_test_cases(),
            |chat: Unauth<_>, pres| async move { chat.extend_avatar_ttl(&pres).await },
            |expected, actual| match expected {
                ExtendAvatarTtlOut::Found(cdn_url) => {
                    assert_eq!(actual.expect("success"), Some(cdn_url))
                }
                ExtendAvatarTtlOut::NotFound => assert_eq!(actual.expect("success"), None),
                ExtendAvatarTtlOut::InvalidCredentials => assert_matches!(
                    actual.expect_err("failure"),
                    RequestError::Other(InvalidAvatarUploadCredentialPresentation)
                ),
            },
        )
    }

    #[test]
    fn test_delete_avatar() {
        run_tests(
            delete_avatar_test_cases(),
            |chat: Unauth<_>, pres| async move { chat.delete_avatar(&pres).await },
            |expected, actual| {
                if expected {
                    actual.expect("success")
                } else {
                    assert_matches!(
                        actual.expect_err("failure"),
                        RequestError::Other(InvalidAvatarUploadCredentialPresentation)
                    )
                }
            },
        )
    }

    #[test]
    fn test_get_avatar_upload_form() {
        run_tests(
            get_avatar_upload_form_test_cases(),
            |chat: Unauth<_>,
             GetAvatarUploadFormArgs {
                 credential,
                 upload_length,
             }| async move {
                chat.get_avatar_upload_form(&credential, upload_length)
                    .await
            },
            |expected, actual| match expected {
                GetAvatarUploadFormOut::Success(s3_upload_form) => {
                    assert_eq!(actual.expect("success"), s3_upload_form)
                }
                GetAvatarUploadFormOut::InvalidCredential => assert_matches!(
                    actual.expect_err("failure"),
                    RequestError::Other(InvalidAvatarUploadCredentialPresentation)
                ),
            },
        );
    }

    #[test]
    fn test_get_avatar_credential() {
        run_tests(
            get_avatar_credential_test_cases(),
            |chat: Auth<_>,
             GetAvatarCredentialArgs {
                 aci,
                 key_pair,
                 rotation_id,
                 server_public_params,
                 current_time,
             }| async move {
                chat.get_avatar_credential(
                    aci,
                    &key_pair,
                    rotation_id,
                    &server_public_params,
                    current_time,
                    &mut profile_utils::test_cases::seeded_rng(0),
                )
                .await
            },
            |expected, actual| match expected {
                Some(cred) => assert_eq!(
                    zkgroup::serialize(&cred),
                    zkgroup::serialize(&actual.expect("valid"))
                ),
                None => assert!(matches!(
                    actual,
                    Err(RequestError::Other(AccountMissingZkCredentialKey))
                )),
            },
        );
    }

    // Not using #[test_case], since it choked on "vec!"
    #[test]
    fn validate_avatar_cdn_url_validation_config() {
        for (prefixes, valid) in [
            (vec![], true),
            (
                vec![
                    "http://localhost:1234/".to_string(),
                    "https://cdn.signal.org/profiles/".to_string(),
                ],
                true,
            ),
            (vec!["ftp://localhost:1234/".to_string()], false),
            (vec!["https://localhost:1234".to_string()], false),
        ] {
            let result = AvatarCdnUrlValidationConfig::new(prefixes);
            if valid {
                result.expect("valid");
            } else {
                result.expect_err("invalid");
            }
        }
    }

    #[test]
    fn validate_url() {
        let config = AvatarCdnUrlValidationConfig::new(vec![
            "http://localhost:8080/profiles/".into(),
            "https://cdn.signal.org/profiles/".into(),
        ])
        .expect("valid");
        for (url, valid) in [
            // So long as a URL starts with the prefix, we call it valid.
            ("https://cdn.signal.org/profiles/", true),
            ("https://cdn.signal.org/profiles/asdf.png", true),
            ("http://localhost:8080/profiles/asdf.png", true),
            ("https://cdn.signal.org/profiles/../asdf.png", false),
            ("https://cdn.signal.org/profiles/..", false),
            ("https://cdn.signal.org/profiles/asdf.png/..", false),
            ("https://example.com/test.png", false),
            ("I am not a URL", false),
            ("https://cdn.signal.org/profiles/img.\u{21B5}.png", false),
            ("https://cdn.signal.org/profiles/img.\u{0000}.png", false),
        ] {
            assert_eq!(config.validate_url(url), valid);
        }
    }

    fn increase_field_len(profile: &mut Profile, field: ProfileFieldWithMaxLength) {
        match field {
            ProfileFieldWithMaxLength::GivenName => profile.given_name.push('C'),
            ProfileFieldWithMaxLength::FamilyName => profile.family_name.push('C'),
            ProfileFieldWithMaxLength::About => profile.about.push('C'),
            ProfileFieldWithMaxLength::AboutEmoji => profile.about_emoji.push('C'),
            ProfileFieldWithMaxLength::Avatar => {
                if let Some(x) = profile.avatar.as_mut() {
                    x.push('C');
                }
            }
            ProfileFieldWithMaxLength::PaymentAddress => {
                if let Some(x) = profile.payment_address.as_mut() {
                    x.push(b'C');
                }
            }
        }
    }

    fn field_is_empty(profile: &Profile, field: ProfileFieldWithMaxLength) -> bool {
        match field {
            ProfileFieldWithMaxLength::GivenName => profile.given_name.is_empty(),
            ProfileFieldWithMaxLength::FamilyName => profile.family_name.is_empty(),
            ProfileFieldWithMaxLength::About => profile.about.is_empty(),
            ProfileFieldWithMaxLength::AboutEmoji => profile.about_emoji.is_empty(),
            ProfileFieldWithMaxLength::Avatar => profile.avatar.is_none(),
            ProfileFieldWithMaxLength::PaymentAddress => profile.payment_address.is_none(),
        }
    }

    #[test]
    fn test_sanitize_single_field_long() {
        for &field in ProfileFieldWithMaxLength::VARIANTS {
            let mut profile = max_length_profile();
            increase_field_len(&mut profile, field);
            let mut errs = Vec::new();
            profile.sanitize(&profile_utils::test_cases::cdn0_config(), &mut errs);
            assert_eq!(errs.len(), 1, "{errs:?}");
            assert_matches!(
                &errs[0],
                ProfileValidationError::FieldTooLong { field: field2, .. } if *field2 == field
            );
            assert!(field_is_empty(&profile, field));
        }
    }

    #[test]
    fn test_sanitize_all_fields_long() {
        let mut profile = max_length_profile();
        for &field in ProfileFieldWithMaxLength::VARIANTS {
            increase_field_len(&mut profile, field);
        }
        let mut errs = Vec::new();
        profile.sanitize(&profile_utils::test_cases::cdn0_config(), &mut errs);
        assert_eq!(
            errs.len(),
            ProfileFieldWithMaxLength::VARIANTS.len(),
            "{errs:?}"
        );
        for &field in ProfileFieldWithMaxLength::VARIANTS {
            assert!(errs.iter().any(|e| matches!(e,
                ProfileValidationError::FieldTooLong { field: field2, .. } if *field2 == field
            )));
            assert!(field_is_empty(&profile, field));
        }
    }

    #[test]
    fn test_sanitize_avatar_url() {
        let mut profile = max_length_profile();
        profile.avatar = Some("http://www.example.com/img.png".into());
        let mut errs = Vec::new();
        profile.sanitize(&profile_utils::test_cases::cdn0_config(), &mut errs);
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert_matches!(&errs[0], ProfileValidationError::AvatarUrlInvalid);
        assert_eq!(profile.avatar, None);
    }
}
