//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::zkgroup;
use libsignal_bridge_macros::*;
use libsignal_protocol::{Aci, Pni, ServiceId};
use zkgroup::auth::*;
use zkgroup::call_links::*;
use zkgroup::generic_server_params::*;
use zkgroup::groups::*;
use zkgroup::profiles::*;
use zkgroup::receipts::*;
use zkgroup::*;

use bincode::Options;
use serde::Deserialize;

use std::convert::TryInto;

use crate::support::*;
use crate::*;

/// Checks that `bytes` can be deserialized as a `T` using our standard bincode settings.
fn validate_serialization<'a, T: Deserialize<'a>>(
    bytes: &'a [u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    // Use the same encoding options as plain bincode::deserialize, but reject trailing bytes.
    // See https://docs.rs/bincode/1.3.3/bincode/config/index.html#options-struct-vs-bincode-functions.
    let strict_options = bincode::DefaultOptions::new().with_fixint_encoding();
    match strict_options.deserialize::<T>(bytes) {
        Ok(_) => Ok(()),
        Err(_) => Err(ZkGroupDeserializationFailure),
    }
}

/// Exposes a ZKGroup serializable type to the bridges via [`FixedLengthSerializable`].
///
/// `fixed_length_serializable!(FooBar)` generates
/// - `impl FixedLengthSerializable for FooBar`, using `[u8; FOO_BAR_LEN]` as the associated array
///   type.
/// - `#[bridge_fn] fn FooBar_CheckValidContents`, which checks that the type can be deserialized.
macro_rules! fixed_length_serializable {
    ($typ:ident) => {
        paste! {
            // Declare a marker type for TypeScript, the same as bridge_handle.
            // (This is harmless for the other bridges.)
            #[doc = "ts: interface " $typ " { readonly __type: unique symbol; }"]
            impl FixedLengthBincodeSerializable for $typ {
                type Array = [u8; [<$typ:snake:upper _LEN>]];
            }
            #[bridge_fn_void]
            fn [<$typ _CheckValidContents>](
                buffer: &[u8]
            ) -> Result<(), ZkGroupDeserializationFailure> {
                if buffer.len() != <$typ as FixedLengthBincodeSerializable>::Array::LEN {
                    return Err(ZkGroupDeserializationFailure)
                }
                validate_serialization::<$typ>(buffer)
            }
        }
    };
}

fixed_length_serializable!(AuthCredential);
fixed_length_serializable!(AuthCredentialResponse);
fixed_length_serializable!(AuthCredentialWithPni);
fixed_length_serializable!(AuthCredentialWithPniResponse);
fixed_length_serializable!(ExpiringProfileKeyCredential);
fixed_length_serializable!(ExpiringProfileKeyCredentialResponse);
fixed_length_serializable!(GroupMasterKey);
fixed_length_serializable!(GroupPublicParams);
fixed_length_serializable!(GroupSecretParams);
fixed_length_serializable!(ProfileKey);
fixed_length_serializable!(ProfileKeyCiphertext);
fixed_length_serializable!(ProfileKeyCommitment);
fixed_length_serializable!(ProfileKeyCredentialRequest);
fixed_length_serializable!(ProfileKeyCredentialRequestContext);
fixed_length_serializable!(ReceiptCredential);
fixed_length_serializable!(ReceiptCredentialPresentation);
fixed_length_serializable!(ReceiptCredentialRequest);
fixed_length_serializable!(ReceiptCredentialRequestContext);
fixed_length_serializable!(ReceiptCredentialResponse);
fixed_length_serializable!(ServerPublicParams);
fixed_length_serializable!(ServerSecretParams);
fixed_length_serializable!(UuidCiphertext);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Timestamp(u64);

impl Timestamp {
    pub(crate) fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    pub(crate) fn as_seconds(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(seconds: u64) -> Self {
        Self::from_seconds(seconds)
    }
}

#[bridge_fn]
fn ProfileKey_GetCommitment(
    profile_key: Serialized<ProfileKey>,
    user_id: Aci,
) -> Serialized<ProfileKeyCommitment> {
    profile_key.get_commitment(user_id).into()
}

#[bridge_fn]
fn ProfileKey_GetProfileKeyVersion(
    profile_key: Serialized<ProfileKey>,
    user_id: Aci,
) -> [u8; PROFILE_KEY_VERSION_ENCODED_LEN] {
    let serialized =
        bincode::serialize(&profile_key.get_profile_key_version(user_id)).expect("can serialize");
    serialized.try_into().expect("right length")
}

#[bridge_fn]
fn ProfileKey_DeriveAccessKey(profile_key: Serialized<ProfileKey>) -> [u8; ACCESS_KEY_LEN] {
    profile_key.derive_access_key()
}

#[bridge_fn]
fn GroupSecretParams_GenerateDeterministic(
    randomness: &[u8; RANDOMNESS_LEN],
) -> Serialized<GroupSecretParams> {
    GroupSecretParams::generate(*randomness).into()
}

#[bridge_fn]
fn GroupSecretParams_DeriveFromMasterKey(
    master_key: Serialized<GroupMasterKey>,
) -> Serialized<GroupSecretParams> {
    GroupSecretParams::derive_from_master_key(master_key.into_inner()).into()
}

// FIXME: Could be bridge_get! if we provide ArgTypeInfo for &GroupSecretParams.
#[bridge_fn]
fn GroupSecretParams_GetMasterKey(
    params: Serialized<GroupSecretParams>,
) -> Serialized<GroupMasterKey> {
    params.get_master_key().into()
}

// FIXME: Could be bridge_get! if we provide ArgTypeInfo for &GroupSecretParams.
#[bridge_fn]
fn GroupSecretParams_GetPublicParams(
    params: Serialized<GroupSecretParams>,
) -> Serialized<GroupPublicParams> {
    params.get_public_params().into()
}

#[bridge_fn]
fn GroupSecretParams_EncryptServiceId(
    params: Serialized<GroupSecretParams>,
    service_id: ServiceId,
) -> Serialized<UuidCiphertext> {
    params.encrypt_service_id(service_id).into()
}

#[bridge_fn]
fn GroupSecretParams_DecryptServiceId(
    params: Serialized<GroupSecretParams>,
    ciphertext: Serialized<UuidCiphertext>,
) -> Result<ServiceId, ZkGroupVerificationFailure> {
    params.decrypt_service_id(ciphertext.into_inner())
}

#[bridge_fn]
fn GroupSecretParams_EncryptProfileKey(
    params: Serialized<GroupSecretParams>,
    profile_key: Serialized<ProfileKey>,
    user_id: Aci,
) -> Serialized<ProfileKeyCiphertext> {
    params
        .encrypt_profile_key(profile_key.into_inner(), user_id)
        .into()
}

#[bridge_fn]
fn GroupSecretParams_DecryptProfileKey(
    params: Serialized<GroupSecretParams>,
    profile_key: Serialized<ProfileKeyCiphertext>,
    user_id: Aci,
) -> Result<Serialized<ProfileKey>, ZkGroupVerificationFailure> {
    Ok(params
        .decrypt_profile_key(profile_key.into_inner(), user_id)?
        .into())
}

#[bridge_fn]
fn GroupSecretParams_EncryptBlobWithPaddingDeterministic(
    params: Serialized<GroupSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    plaintext: &[u8],
    padding_len: u32,
) -> Vec<u8> {
    params.encrypt_blob_with_padding(*randomness, plaintext, padding_len)
}

#[bridge_fn]
fn GroupSecretParams_DecryptBlobWithPadding(
    params: Serialized<GroupSecretParams>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    params.decrypt_blob_with_padding(ciphertext)
}

#[bridge_fn]
fn ServerSecretParams_GenerateDeterministic(
    randomness: &[u8; RANDOMNESS_LEN],
) -> Serialized<ServerSecretParams> {
    ServerSecretParams::generate(*randomness).into()
}

// FIXME: Could be bridge_get!
#[bridge_fn]
fn ServerSecretParams_GetPublicParams(
    params: Serialized<ServerSecretParams>,
) -> Serialized<ServerPublicParams> {
    params.get_public_params().into()
}

#[bridge_fn]
fn ServerSecretParams_SignDeterministic(
    params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    message: &[u8],
) -> [u8; SIGNATURE_LEN] {
    params.sign(*randomness, message)
}

#[bridge_fn]
fn ServerPublicParams_ReceiveAuthCredential(
    params: Serialized<ServerPublicParams>,
    aci: Aci,
    redemption_time: u32,
    response: Serialized<AuthCredentialResponse>,
) -> Result<Serialized<AuthCredential>, ZkGroupVerificationFailure> {
    Ok(params
        .receive_auth_credential(aci, redemption_time, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(
    params: Serialized<ServerPublicParams>,
    aci: Aci,
    pni: Pni,
    redemption_time: Timestamp,
    response: Serialized<AuthCredentialWithPniResponse>,
) -> Result<Serialized<AuthCredentialWithPni>, ZkGroupVerificationFailure> {
    Ok(params
        .receive_auth_credential_with_pni_as_service_id(
            aci,
            pni,
            redemption_time.as_seconds(),
            &response,
        )?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_ReceiveAuthCredentialWithPniAsAci(
    params: Serialized<ServerPublicParams>,
    aci: Aci,
    pni: Pni,
    redemption_time: Timestamp,
    response: Serialized<AuthCredentialWithPniResponse>,
) -> Result<Serialized<AuthCredentialWithPni>, ZkGroupVerificationFailure> {
    Ok(params
        .receive_auth_credential_with_pni_as_aci(aci, pni, redemption_time.as_seconds(), &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateAuthCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    auth_credential: Serialized<AuthCredential>,
) -> Vec<u8> {
    bincode::serialize(&server_public_params.create_auth_credential_presentation(
        *randomness,
        group_secret_params.into_inner(),
        auth_credential.into_inner(),
    ))
    .expect("can serialize")
}

#[bridge_fn]
fn ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    auth_credential: Serialized<AuthCredentialWithPni>,
) -> Vec<u8> {
    bincode::serialize(
        &server_public_params.create_auth_credential_with_pni_presentation(
            *randomness,
            group_secret_params.into_inner(),
            auth_credential.into_inner(),
        ),
    )
    .expect("can serialize")
}

#[bridge_fn]
fn ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    user_id: Aci,
    profile_key: Serialized<ProfileKey>,
) -> Serialized<ProfileKeyCredentialRequestContext> {
    server_public_params
        .create_profile_key_credential_request_context(
            *randomness,
            user_id,
            profile_key.into_inner(),
        )
        .into()
}

#[bridge_fn]
fn ServerPublicParams_ReceiveExpiringProfileKeyCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<ProfileKeyCredentialRequestContext>,
    response: Serialized<ExpiringProfileKeyCredentialResponse>,
    current_time_in_seconds: Timestamp,
) -> Result<Serialized<ExpiringProfileKeyCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_expiring_profile_key_credential(
            &request_context,
            &response,
            current_time_in_seconds.as_seconds(),
        )?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<ExpiringProfileKeyCredential>,
) -> Vec<u8> {
    bincode::serialize(
        &server_public_params.create_expiring_profile_key_credential_presentation(
            *randomness,
            group_secret_params.into_inner(),
            profile_key_credential.into_inner(),
        ),
    )
    .expect("can serialize")
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_serial: &[u8; RECEIPT_SERIAL_LEN],
) -> Serialized<ReceiptCredentialRequestContext> {
    server_public_params
        .create_receipt_credential_request_context(*randomness, *receipt_serial)
        .into()
}

#[bridge_fn]
fn ServerPublicParams_ReceiveReceiptCredential(
    server_public_params: Serialized<ServerPublicParams>,
    request_context: Serialized<ReceiptCredentialRequestContext>,
    response: Serialized<ReceiptCredentialResponse>,
) -> Result<Serialized<ReceiptCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_receipt_credential(&request_context, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(
    server_public_params: Serialized<ServerPublicParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_credential: Serialized<ReceiptCredential>,
) -> Serialized<ReceiptCredentialPresentation> {
    server_public_params
        .create_receipt_credential_presentation(*randomness, &receipt_credential)
        .into()
}

#[bridge_fn]
fn ServerSecretParams_IssueAuthCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    aci: Aci,
    redemption_time: u32,
) -> Serialized<AuthCredentialResponse> {
    server_secret_params
        .issue_auth_credential(*randomness, aci, redemption_time)
        .into()
}

#[bridge_fn]
fn ServerSecretParams_IssueAuthCredentialWithPniAsServiceIdDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    aci: Aci,
    pni: Pni,
    redemption_time: Timestamp,
) -> Serialized<AuthCredentialWithPniResponse> {
    server_secret_params
        .issue_auth_credential_with_pni_as_service_id(
            *randomness,
            aci,
            pni,
            redemption_time.as_seconds(),
        )
        .into()
}

#[bridge_fn]
fn ServerSecretParams_IssueAuthCredentialWithPniAsAciDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    aci: Aci,
    pni: Pni,
    redemption_time: Timestamp,
) -> Serialized<AuthCredentialWithPniResponse> {
    server_secret_params
        .issue_auth_credential_with_pni_as_aci(*randomness, aci, pni, redemption_time.as_seconds())
        .into()
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyAuthCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: &[u8],
    current_time_in_seconds: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    server_secret_params.verify_auth_credential_presentation(
        group_public_params.into_inner(),
        &presentation,
        current_time_in_seconds.as_seconds(),
    )
}

#[bridge_fn]
fn ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ProfileKeyCredentialRequest>,
    user_id: Aci,
    commitment: Serialized<ProfileKeyCommitment>,
    expiration_in_seconds: Timestamp,
) -> Result<Serialized<ExpiringProfileKeyCredentialResponse>, ZkGroupVerificationFailure> {
    Ok(server_secret_params
        .issue_expiring_profile_key_credential(
            *randomness,
            &request,
            user_id,
            commitment.into_inner(),
            expiration_in_seconds.as_seconds(),
        )?
        .into())
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyProfileKeyCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: &[u8],
    current_time_in_seconds: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    server_secret_params.verify_profile_key_credential_presentation(
        group_public_params.into_inner(),
        &presentation,
        current_time_in_seconds.as_seconds(),
    )
}

#[bridge_fn]
fn ServerSecretParams_IssueReceiptCredentialDeterministic(
    server_secret_params: Serialized<ServerSecretParams>,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ReceiptCredentialRequest>,
    receipt_expiration_time: Timestamp,
    receipt_level: u64,
) -> Serialized<ReceiptCredentialResponse> {
    server_secret_params
        .issue_receipt_credential(
            *randomness,
            &request,
            receipt_expiration_time.as_seconds(),
            receipt_level,
        )
        .into()
}

#[bridge_fn_void]
fn ServerSecretParams_VerifyReceiptCredentialPresentation(
    server_secret_params: Serialized<ServerSecretParams>,
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> Result<(), ZkGroupVerificationFailure> {
    server_secret_params.verify_receipt_credential_presentation(&presentation)
}

// FIXME: Should be bridge_get!
#[bridge_fn]
fn GroupPublicParams_GetGroupIdentifier(
    group_public_params: Serialized<GroupPublicParams>,
) -> [u8; GROUP_IDENTIFIER_LEN] {
    group_public_params.get_group_identifier()
}

#[bridge_fn_void]
fn ServerPublicParams_VerifySignature(
    server_public_params: Serialized<ServerPublicParams>,
    message: &[u8],
    notary_signature: &[u8; SIGNATURE_LEN],
) -> Result<(), ZkGroupVerificationFailure> {
    server_public_params.verify_signature(message, *notary_signature)
}

#[bridge_fn_void]
fn AuthCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    AnyAuthCredentialPresentation::new(presentation_bytes)?;
    Ok(())
}

#[bridge_fn]
fn AuthCredentialPresentation_GetUuidCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_uuid_ciphertext().into()
}

#[bridge_fn(ffi = false)]
fn AuthCredentialPresentation_GetPniCiphertext(presentation_bytes: &[u8]) -> Option<Vec<u8>> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation
        .get_pni_ciphertext()
        .map(|ciphertext| bincode::serialize(&ciphertext).expect("can serialize"))
}

#[bridge_fn(jni = false, node = false)]
fn AuthCredentialPresentation_GetPniCiphertextOrEmpty(presentation_bytes: &[u8]) -> Vec<u8> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation
        .get_pni_ciphertext()
        .map(|ciphertext| bincode::serialize(&ciphertext).expect("can serialize"))
        .unwrap_or_default()
}

#[bridge_fn]
fn AuthCredentialPresentation_GetRedemptionTime(presentation_bytes: &[u8]) -> Timestamp {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    Timestamp::from_seconds(presentation.get_redemption_time())
}

// FIXME: bridge_get
#[bridge_fn]
fn ProfileKeyCredentialRequestContext_GetRequest(
    context: Serialized<ProfileKeyCredentialRequestContext>,
) -> Serialized<ProfileKeyCredentialRequest> {
    context.get_request().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ExpiringProfileKeyCredential_GetExpirationTime(
    credential: Serialized<ExpiringProfileKeyCredential>,
) -> Timestamp {
    credential.get_expiration_time().into()
}

#[bridge_fn_void]
fn ProfileKeyCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    AnyProfileKeyCredentialPresentation::new(presentation_bytes)?;
    Ok(())
}

#[bridge_fn]
fn ProfileKeyCredentialPresentation_GetUuidCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_uuid_ciphertext().into()
}

#[bridge_fn]
fn ProfileKeyCredentialPresentation_GetProfileKeyCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<ProfileKeyCiphertext> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_profile_key_ciphertext().into()
}

// Only used by the server.
#[bridge_fn(ffi = false, node = false)]
fn ProfileKeyCredentialPresentation_GetStructurallyValidV1PresentationBytes(
    presentation_bytes: &[u8],
) -> Vec<u8> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.to_structurally_valid_v1_presentation_bytes()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialRequestContext_GetRequest(
    request_context: Serialized<ReceiptCredentialRequestContext>,
) -> Serialized<ReceiptCredentialRequest> {
    request_context.get_request().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredential_GetReceiptExpirationTime(
    receipt_credential: Serialized<ReceiptCredential>,
) -> Timestamp {
    receipt_credential.get_receipt_expiration_time().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredential_GetReceiptLevel(receipt_credential: Serialized<ReceiptCredential>) -> u64 {
    receipt_credential.get_receipt_level()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialPresentation_GetReceiptExpirationTime(
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> Timestamp {
    presentation.get_receipt_expiration_time().into()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialPresentation_GetReceiptLevel(
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> u64 {
    presentation.get_receipt_level()
}

// FIXME: bridge_get
#[bridge_fn]
fn ReceiptCredentialPresentation_GetReceiptSerial(
    presentation: Serialized<ReceiptCredentialPresentation>,
) -> [u8; RECEIPT_SERIAL_LEN] {
    presentation.get_receipt_serial_bytes()
}

#[bridge_fn_void]
fn GenericServerSecretParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GenericServerSecretParams>(params_bytes)
}

#[bridge_fn]
fn GenericServerSecretParams_GenerateDeterministic(randomness: &[u8; RANDOMNESS_LEN]) -> Vec<u8> {
    let params = GenericServerSecretParams::generate(*randomness);
    bincode::serialize(&params).expect("can serialize")
}

#[bridge_fn]
fn GenericServerSecretParams_GetPublicParams(params_bytes: &[u8]) -> Vec<u8> {
    let params = bincode::deserialize::<GenericServerSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let public_params = params.get_public_params();
    bincode::serialize(&public_params).expect("can serialize")
}

#[bridge_fn_void]
fn GenericServerPublicParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GenericServerPublicParams>(params_bytes)
}

#[bridge_fn_void]
fn CallLinkSecretParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkSecretParams>(params_bytes)
}

#[bridge_fn]
fn CallLinkSecretParams_DeriveFromRootKey(root_key: &[u8]) -> Vec<u8> {
    let params = CallLinkSecretParams::derive_from_root_key(root_key);
    bincode::serialize(&params).expect("can serialize")
}

#[bridge_fn]
fn CallLinkSecretParams_GetPublicParams(params_bytes: &[u8]) -> Vec<u8> {
    let params = bincode::deserialize::<CallLinkSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let public_params = params.get_public_params();
    bincode::serialize(&public_params).expect("can serialize")
}

#[bridge_fn]
fn CallLinkSecretParams_DecryptUserId(
    params_bytes: &[u8],
    user_id: Serialized<UuidCiphertext>,
) -> Result<Aci, ZkGroupVerificationFailure> {
    let params = bincode::deserialize::<CallLinkSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    params.decrypt_uid(user_id.into_inner())
}

#[bridge_fn_void]
fn CallLinkPublicParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkPublicParams>(params_bytes)
}

#[bridge_fn_void]
fn CreateCallLinkCredentialRequestContext_CheckValidContents(
    context_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CreateCallLinkCredentialRequestContext>(context_bytes)
}

#[bridge_fn]
fn CreateCallLinkCredentialRequestContext_NewDeterministic(
    room_id: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Vec<u8> {
    let context = CreateCallLinkCredentialRequestContext::new(room_id, *randomness);
    bincode::serialize(&context).expect("can serialize")
}

#[bridge_fn]
fn CreateCallLinkCredentialRequestContext_GetRequest(context_bytes: &[u8]) -> Vec<u8> {
    let context = bincode::deserialize::<CreateCallLinkCredentialRequestContext>(context_bytes)
        .expect("should have been parsed previously");

    let request = context.get_request();
    bincode::serialize(&request).expect("can serialize")
}

#[bridge_fn_void]
fn CreateCallLinkCredentialRequest_CheckValidContents(
    request_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CreateCallLinkCredentialRequest>(request_bytes)
}

#[bridge_fn]
fn CreateCallLinkCredentialRequest_IssueDeterministic(
    request_bytes: &[u8],
    user_id: Aci,
    timestamp: Timestamp,
    params_bytes: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Vec<u8> {
    let request = bincode::deserialize::<CreateCallLinkCredentialRequest>(request_bytes)
        .expect("should have been parsed previously");
    let params = bincode::deserialize::<GenericServerSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let response = request.issue(user_id, timestamp.as_seconds(), &params, *randomness);
    bincode::serialize(&response).expect("can serialize")
}

#[bridge_fn_void]
fn CreateCallLinkCredentialResponse_CheckValidContents(
    response_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CreateCallLinkCredentialResponse>(response_bytes)
}

#[bridge_fn]
fn CreateCallLinkCredentialRequestContext_ReceiveResponse(
    context_bytes: &[u8],
    response_bytes: &[u8],
    user_id: Aci,
    params_bytes: &[u8],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let context = bincode::deserialize::<CreateCallLinkCredentialRequestContext>(context_bytes)
        .expect("should have been parsed previously");
    let response = bincode::deserialize::<CreateCallLinkCredentialResponse>(response_bytes)
        .expect("should have been parsed previously");
    let params = bincode::deserialize::<GenericServerPublicParams>(params_bytes)
        .expect("should have been parsed previously");

    let credential = context.receive(response, user_id, &params)?;
    Ok(bincode::serialize(&credential).expect("can serialize"))
}

#[bridge_fn_void]
fn CreateCallLinkCredential_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CreateCallLinkCredential>(params_bytes)
}

#[bridge_fn]
fn CreateCallLinkCredential_PresentDeterministic(
    credential_bytes: &[u8],
    room_id: &[u8],
    user_id: Aci,
    server_params_bytes: &[u8],
    call_link_params_bytes: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let credential = bincode::deserialize::<CreateCallLinkCredential>(credential_bytes)
        .expect("should have been parsed previously");
    let server_params = bincode::deserialize::<GenericServerPublicParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = bincode::deserialize::<CallLinkSecretParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    let presentation = credential.present(
        room_id,
        user_id,
        &server_params,
        &call_link_params,
        *randomness,
    );
    Ok(bincode::serialize(&presentation).expect("can serialize"))
}

#[bridge_fn_void]
fn CreateCallLinkCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CreateCallLinkCredentialPresentation>(presentation_bytes)
}

#[bridge_fn_void]
fn CreateCallLinkCredentialPresentation_Verify(
    presentation_bytes: &[u8],
    room_id: &[u8],
    now: Timestamp,
    server_params_bytes: &[u8],
    call_link_params_bytes: &[u8],
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation =
        bincode::deserialize::<CreateCallLinkCredentialPresentation>(presentation_bytes)
            .expect("should have been parsed previously");
    let server_params = bincode::deserialize::<GenericServerSecretParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = bincode::deserialize::<CallLinkPublicParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    presentation.verify(room_id, now.as_seconds(), &server_params, &call_link_params)
}

#[bridge_fn_void]
fn CallLinkAuthCredentialResponse_CheckValidContents(
    response_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkAuthCredentialResponse>(response_bytes)
}

#[bridge_fn]
fn CallLinkAuthCredentialResponse_IssueDeterministic(
    user_id: Aci,
    redemption_time: Timestamp,
    params_bytes: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Vec<u8> {
    let params = bincode::deserialize::<GenericServerSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let response = CallLinkAuthCredentialResponse::issue_credential(
        user_id,
        redemption_time.as_seconds(),
        &params,
        *randomness,
    );
    bincode::serialize(&response).expect("can serialize")
}

#[bridge_fn]
fn CallLinkAuthCredentialResponse_Receive(
    response_bytes: &[u8],
    user_id: Aci,
    redemption_time: Timestamp,
    params_bytes: &[u8],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let response = bincode::deserialize::<CallLinkAuthCredentialResponse>(response_bytes)
        .expect("should have been parsed previously");
    let params = bincode::deserialize::<GenericServerPublicParams>(params_bytes)
        .expect("should have been parsed previously");

    let credential = response.receive(user_id, redemption_time.as_seconds(), &params)?;
    Ok(bincode::serialize(&credential).expect("can serialize"))
}

#[bridge_fn_void]
fn CallLinkAuthCredential_CheckValidContents(
    credential_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkAuthCredential>(credential_bytes)
}

#[bridge_fn]
fn CallLinkAuthCredential_PresentDeterministic(
    credential_bytes: &[u8],
    user_id: Aci,
    redemption_time: Timestamp,
    server_params_bytes: &[u8],
    call_link_params_bytes: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let credential = bincode::deserialize::<CallLinkAuthCredential>(credential_bytes)
        .expect("should have been parsed previously");
    let server_params = bincode::deserialize::<GenericServerPublicParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = bincode::deserialize::<CallLinkSecretParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    let presentation = credential.present(
        user_id,
        redemption_time.as_seconds(),
        &server_params,
        &call_link_params,
        *randomness,
    );
    Ok(bincode::serialize(&presentation).expect("can serialize"))
}

#[bridge_fn_void]
fn CallLinkAuthCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkAuthCredentialPresentation>(presentation_bytes)
}

#[bridge_fn_void]
fn CallLinkAuthCredentialPresentation_Verify(
    presentation_bytes: &[u8],
    now: Timestamp,
    server_params_bytes: &[u8],
    call_link_params_bytes: &[u8],
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation =
        bincode::deserialize::<CallLinkAuthCredentialPresentation>(presentation_bytes)
            .expect("should have been parsed previously");
    let server_params = bincode::deserialize::<GenericServerSecretParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = bincode::deserialize::<CallLinkPublicParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    presentation.verify(now.as_seconds(), &server_params, &call_link_params)
}

#[bridge_fn]
fn CallLinkAuthCredentialPresentation_GetUserId(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation =
        bincode::deserialize::<CallLinkAuthCredentialPresentation>(presentation_bytes)
            .expect("should have been parsed previously");

    presentation.get_user_id().into()
}
