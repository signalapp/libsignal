//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::zkgroup;
use backups::BackupCredentialType;
use libsignal_bridge_macros::*;
use libsignal_bridge_types::zkgroup::validate_serialization;
use libsignal_protocol::{Aci, Pni, ServiceId};
use uuid::Uuid;
use zkgroup::auth::*;
use zkgroup::backups::{
    BackupAuthCredential, BackupAuthCredentialPresentation, BackupAuthCredentialRequest,
    BackupAuthCredentialRequestContext, BackupAuthCredentialResponse, BackupLevel,
};
use zkgroup::call_links::*;
use zkgroup::generic_server_params::*;
use zkgroup::groups::*;
use zkgroup::profiles::*;
use zkgroup::receipts::*;
pub(crate) use zkgroup::Timestamp;
use zkgroup::*;

use crate::support::*;
use crate::*;

bridge_fixed_length_serializable_fns!(ExpiringProfileKeyCredential);
bridge_fixed_length_serializable_fns!(ExpiringProfileKeyCredentialResponse);
bridge_fixed_length_serializable_fns!(GroupMasterKey);
bridge_fixed_length_serializable_fns!(GroupPublicParams);
bridge_fixed_length_serializable_fns!(GroupSecretParams);
bridge_fixed_length_serializable_fns!(ProfileKey);
bridge_fixed_length_serializable_fns!(ProfileKeyCiphertext);
bridge_fixed_length_serializable_fns!(ProfileKeyCommitment);
bridge_fixed_length_serializable_fns!(ProfileKeyCredentialRequest);
bridge_fixed_length_serializable_fns!(ProfileKeyCredentialRequestContext);
bridge_fixed_length_serializable_fns!(ReceiptCredential);
bridge_fixed_length_serializable_fns!(ReceiptCredentialPresentation);
bridge_fixed_length_serializable_fns!(ReceiptCredentialRequest);
bridge_fixed_length_serializable_fns!(ReceiptCredentialRequestContext);
bridge_fixed_length_serializable_fns!(ReceiptCredentialResponse);
bridge_fixed_length_serializable_fns!(UuidCiphertext);

bridge_serializable_handle_fns!(ServerPublicParams);
bridge_serializable_handle_fns!(ServerSecretParams);

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
    let serialized = zkgroup::serialize(&profile_key.get_profile_key_version(user_id));
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
) -> ServerSecretParams {
    ServerSecretParams::generate(*randomness)
}

// FIXME: Could be bridge_get!
#[bridge_fn]
fn ServerSecretParams_GetPublicParams(params: &ServerSecretParams) -> ServerPublicParams {
    params.get_public_params()
}

#[bridge_fn]
fn ServerSecretParams_SignDeterministic(
    params: &ServerSecretParams,
    randomness: &[u8; RANDOMNESS_LEN],
    message: &[u8],
) -> [u8; SIGNATURE_LEN] {
    params.sign(*randomness, message)
}

#[bridge_fn]
fn ServerPublicParams_ReceiveAuthCredentialWithPniAsServiceId(
    params: &ServerPublicParams,
    aci: Aci,
    pni: Pni,
    redemption_time: Timestamp,
    auth_credential_with_pni_response_bytes: &[u8],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let response = AuthCredentialWithPniResponse::new(auth_credential_with_pni_response_bytes)
        .expect("previously validated");
    Ok(zkgroup::serialize(&response.receive(
        params,
        aci,
        pni,
        redemption_time,
    )?))
}

#[bridge_fn]
fn ServerPublicParams_CreateAuthCredentialWithPniPresentationDeterministic(
    server_public_params: &ServerPublicParams,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    auth_credential_with_pni_bytes: &[u8],
) -> Vec<u8> {
    let auth_credential =
        AuthCredentialWithPni::new(auth_credential_with_pni_bytes).expect("previously validated");
    zkgroup::serialize(&auth_credential.present(
        server_public_params,
        &group_secret_params.into_inner(),
        *randomness,
    ))
}

#[bridge_fn]
fn ServerPublicParams_CreateProfileKeyCredentialRequestContextDeterministic(
    server_public_params: &ServerPublicParams,
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
    server_public_params: &ServerPublicParams,
    request_context: Serialized<ProfileKeyCredentialRequestContext>,
    response: Serialized<ExpiringProfileKeyCredentialResponse>,
    current_time_in_seconds: Timestamp,
) -> Result<Serialized<ExpiringProfileKeyCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_expiring_profile_key_credential(
            &request_context,
            &response,
            current_time_in_seconds,
        )?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateExpiringProfileKeyCredentialPresentationDeterministic(
    server_public_params: &ServerPublicParams,
    randomness: &[u8; RANDOMNESS_LEN],
    group_secret_params: Serialized<GroupSecretParams>,
    profile_key_credential: Serialized<ExpiringProfileKeyCredential>,
) -> Vec<u8> {
    zkgroup::serialize(
        &server_public_params.create_expiring_profile_key_credential_presentation(
            *randomness,
            group_secret_params.into_inner(),
            profile_key_credential.into_inner(),
        ),
    )
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialRequestContextDeterministic(
    server_public_params: &ServerPublicParams,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_serial: &[u8; RECEIPT_SERIAL_LEN],
) -> Serialized<ReceiptCredentialRequestContext> {
    server_public_params
        .create_receipt_credential_request_context(*randomness, *receipt_serial)
        .into()
}

#[bridge_fn]
fn ServerPublicParams_ReceiveReceiptCredential(
    server_public_params: &ServerPublicParams,
    request_context: Serialized<ReceiptCredentialRequestContext>,
    response: Serialized<ReceiptCredentialResponse>,
) -> Result<Serialized<ReceiptCredential>, ZkGroupVerificationFailure> {
    Ok(server_public_params
        .receive_receipt_credential(&request_context, &response)?
        .into())
}

#[bridge_fn]
fn ServerPublicParams_CreateReceiptCredentialPresentationDeterministic(
    server_public_params: &ServerPublicParams,
    randomness: &[u8; RANDOMNESS_LEN],
    receipt_credential: Serialized<ReceiptCredential>,
) -> Serialized<ReceiptCredentialPresentation> {
    server_public_params
        .create_receipt_credential_presentation(*randomness, &receipt_credential)
        .into()
}

#[bridge_fn]
fn ServerSecretParams_IssueAuthCredentialWithPniZkcDeterministic(
    server_secret_params: &ServerSecretParams,
    randomness: &[u8; RANDOMNESS_LEN],
    aci: Aci,
    pni: Pni,
    redemption_time: Timestamp,
) -> Vec<u8> {
    zkgroup::serialize(&AuthCredentialWithPniZkcResponse::issue_credential(
        aci,
        pni,
        redemption_time,
        server_secret_params,
        *randomness,
    ))
}

#[bridge_fn]
fn AuthCredentialWithPni_CheckValidContents(
    bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    AuthCredentialWithPni::new(bytes).map(|_| ())
}

#[bridge_fn]
fn AuthCredentialWithPniResponse_CheckValidContents(
    bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    AuthCredentialWithPniResponse::new(bytes).map(|_| ())
}

#[bridge_fn]
fn ServerSecretParams_VerifyAuthCredentialPresentation(
    server_secret_params: &ServerSecretParams,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: &[u8],
    current_time_in_seconds: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    server_secret_params.verify_auth_credential_presentation(
        group_public_params.into_inner(),
        &presentation,
        current_time_in_seconds,
    )
}

#[bridge_fn]
fn ServerSecretParams_IssueExpiringProfileKeyCredentialDeterministic(
    server_secret_params: &ServerSecretParams,
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
            expiration_in_seconds,
        )?
        .into())
}

#[bridge_fn]
fn ServerSecretParams_VerifyProfileKeyCredentialPresentation(
    server_secret_params: &ServerSecretParams,
    group_public_params: Serialized<GroupPublicParams>,
    presentation_bytes: &[u8],
    current_time_in_seconds: Timestamp,
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = AnyProfileKeyCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    server_secret_params.verify_profile_key_credential_presentation(
        group_public_params.into_inner(),
        &presentation,
        current_time_in_seconds,
    )
}

#[bridge_fn]
fn ServerSecretParams_IssueReceiptCredentialDeterministic(
    server_secret_params: &ServerSecretParams,
    randomness: &[u8; RANDOMNESS_LEN],
    request: Serialized<ReceiptCredentialRequest>,
    receipt_expiration_time: Timestamp,
    receipt_level: u64,
) -> Serialized<ReceiptCredentialResponse> {
    server_secret_params
        .issue_receipt_credential(
            *randomness,
            &request,
            receipt_expiration_time,
            receipt_level,
        )
        .into()
}

#[bridge_fn]
fn ServerSecretParams_VerifyReceiptCredentialPresentation(
    server_secret_params: &ServerSecretParams,
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

#[bridge_fn]
fn ServerPublicParams_VerifySignature(
    server_public_params: &ServerPublicParams,
    message: &[u8],
    notary_signature: &[u8; SIGNATURE_LEN],
) -> Result<(), ZkGroupVerificationFailure> {
    server_public_params.verify_signature(message, *notary_signature)
}

#[bridge_fn]
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
    presentation.get_aci_ciphertext().into()
}

#[bridge_fn]
fn AuthCredentialPresentation_GetPniCiphertext(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_pni_ciphertext().into()
}

#[bridge_fn]
fn AuthCredentialPresentation_GetRedemptionTime(presentation_bytes: &[u8]) -> Timestamp {
    let presentation = AnyAuthCredentialPresentation::new(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.get_redemption_time()
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
    credential.get_expiration_time()
}

#[bridge_fn]
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
    receipt_credential.get_receipt_expiration_time()
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
    presentation.get_receipt_expiration_time()
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

#[bridge_fn]
fn GenericServerSecretParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GenericServerSecretParams>(params_bytes)
}

#[bridge_fn]
fn GenericServerSecretParams_GenerateDeterministic(randomness: &[u8; RANDOMNESS_LEN]) -> Vec<u8> {
    let params = GenericServerSecretParams::generate(*randomness);
    zkgroup::serialize(&params)
}

#[bridge_fn]
fn GenericServerSecretParams_GetPublicParams(params_bytes: &[u8]) -> Vec<u8> {
    let params = zkgroup::deserialize::<GenericServerSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let public_params = params.get_public_params();
    zkgroup::serialize(&public_params)
}

#[bridge_fn]
fn GenericServerPublicParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GenericServerPublicParams>(params_bytes)
}

#[bridge_fn]
fn CallLinkSecretParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkSecretParams>(params_bytes)
}

#[bridge_fn]
fn CallLinkSecretParams_DeriveFromRootKey(root_key: &[u8]) -> Vec<u8> {
    let params = CallLinkSecretParams::derive_from_root_key(root_key);
    zkgroup::serialize(&params)
}

#[bridge_fn]
fn CallLinkSecretParams_GetPublicParams(params_bytes: &[u8]) -> Vec<u8> {
    let params = zkgroup::deserialize::<CallLinkSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let public_params = params.get_public_params();
    zkgroup::serialize(&public_params)
}

#[bridge_fn]
fn CallLinkSecretParams_DecryptUserId(
    params_bytes: &[u8],
    user_id: Serialized<UuidCiphertext>,
) -> Result<Aci, ZkGroupVerificationFailure> {
    let params = zkgroup::deserialize::<CallLinkSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    params.decrypt_uid(user_id.into_inner())
}

#[bridge_fn]
fn CallLinkPublicParams_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkPublicParams>(params_bytes)
}

#[bridge_fn]
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
    zkgroup::serialize(&context)
}

#[bridge_fn]
fn CreateCallLinkCredentialRequestContext_GetRequest(context_bytes: &[u8]) -> Vec<u8> {
    let context = zkgroup::deserialize::<CreateCallLinkCredentialRequestContext>(context_bytes)
        .expect("should have been parsed previously");

    let request = context.get_request();
    zkgroup::serialize(&request)
}

#[bridge_fn]
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
    let request = zkgroup::deserialize::<CreateCallLinkCredentialRequest>(request_bytes)
        .expect("should have been parsed previously");
    let params = zkgroup::deserialize::<GenericServerSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let response = request.issue(user_id, timestamp, &params, *randomness);
    zkgroup::serialize(&response)
}

#[bridge_fn]
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
    let context = zkgroup::deserialize::<CreateCallLinkCredentialRequestContext>(context_bytes)
        .expect("should have been parsed previously");
    let response = zkgroup::deserialize::<CreateCallLinkCredentialResponse>(response_bytes)
        .expect("should have been parsed previously");
    let params = zkgroup::deserialize::<GenericServerPublicParams>(params_bytes)
        .expect("should have been parsed previously");

    let credential = context.receive(response, user_id, &params)?;
    Ok(zkgroup::serialize(&credential))
}

#[bridge_fn]
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
    let credential = zkgroup::deserialize::<CreateCallLinkCredential>(credential_bytes)
        .expect("should have been parsed previously");
    let server_params = zkgroup::deserialize::<GenericServerPublicParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = zkgroup::deserialize::<CallLinkSecretParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    let presentation = credential.present(
        room_id,
        user_id,
        &server_params,
        &call_link_params,
        *randomness,
    );
    Ok(zkgroup::serialize(&presentation))
}

#[bridge_fn]
fn CreateCallLinkCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CreateCallLinkCredentialPresentation>(presentation_bytes)
}

#[bridge_fn]
fn CreateCallLinkCredentialPresentation_Verify(
    presentation_bytes: &[u8],
    room_id: &[u8],
    now: Timestamp,
    server_params_bytes: &[u8],
    call_link_params_bytes: &[u8],
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation =
        zkgroup::deserialize::<CreateCallLinkCredentialPresentation>(presentation_bytes)
            .expect("should have been parsed previously");
    let server_params = zkgroup::deserialize::<GenericServerSecretParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = zkgroup::deserialize::<CallLinkPublicParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    presentation.verify(room_id, now, &server_params, &call_link_params)
}

#[bridge_fn]
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
    let params = zkgroup::deserialize::<GenericServerSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let response = CallLinkAuthCredentialResponse::issue_credential(
        user_id,
        redemption_time,
        &params,
        *randomness,
    );
    zkgroup::serialize(&response)
}

#[bridge_fn]
fn CallLinkAuthCredentialResponse_Receive(
    response_bytes: &[u8],
    user_id: Aci,
    redemption_time: Timestamp,
    params_bytes: &[u8],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let response = zkgroup::deserialize::<CallLinkAuthCredentialResponse>(response_bytes)
        .expect("should have been parsed previously");
    let params = zkgroup::deserialize::<GenericServerPublicParams>(params_bytes)
        .expect("should have been parsed previously");

    let credential = response.receive(user_id, redemption_time, &params)?;
    Ok(zkgroup::serialize(&credential))
}

#[bridge_fn]
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
    let credential = zkgroup::deserialize::<CallLinkAuthCredential>(credential_bytes)
        .expect("should have been parsed previously");
    let server_params = zkgroup::deserialize::<GenericServerPublicParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = zkgroup::deserialize::<CallLinkSecretParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    let presentation = credential.present(
        user_id,
        redemption_time,
        &server_params,
        &call_link_params,
        *randomness,
    );
    Ok(zkgroup::serialize(&presentation))
}

#[bridge_fn]
fn CallLinkAuthCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<CallLinkAuthCredentialPresentation>(presentation_bytes)
}

#[bridge_fn]
fn CallLinkAuthCredentialPresentation_Verify(
    presentation_bytes: &[u8],
    now: Timestamp,
    server_params_bytes: &[u8],
    call_link_params_bytes: &[u8],
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation =
        zkgroup::deserialize::<CallLinkAuthCredentialPresentation>(presentation_bytes)
            .expect("should have been parsed previously");
    let server_params = zkgroup::deserialize::<GenericServerSecretParams>(server_params_bytes)
        .expect("should have been parsed previously");
    let call_link_params = zkgroup::deserialize::<CallLinkPublicParams>(call_link_params_bytes)
        .expect("should have been parsed previously");

    presentation.verify(now, &server_params, &call_link_params)
}

#[bridge_fn]
fn CallLinkAuthCredentialPresentation_GetUserId(
    presentation_bytes: &[u8],
) -> Serialized<UuidCiphertext> {
    let presentation =
        zkgroup::deserialize::<CallLinkAuthCredentialPresentation>(presentation_bytes)
            .expect("should have been parsed previously");

    presentation.get_user_id().into()
}

#[bridge_fn]
fn BackupAuthCredentialRequestContext_New(backup_key: &[u8; 32], uuid: Uuid) -> Vec<u8> {
    let backup_key: libsignal_account_keys::BackupKey =
        libsignal_account_keys::BackupKey(*backup_key);
    let context = BackupAuthCredentialRequestContext::new(&backup_key, uuid.into());
    zkgroup::serialize(&context)
}

#[bridge_fn]
fn BackupAuthCredentialRequestContext_CheckValidContents(
    context_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<BackupAuthCredentialRequestContext>(context_bytes)
}

#[bridge_fn]
fn BackupAuthCredentialRequestContext_GetRequest(context_bytes: &[u8]) -> Vec<u8> {
    let context = bincode::deserialize::<BackupAuthCredentialRequestContext>(context_bytes)
        .expect("should have been parsed previously");

    let request = context.get_request();
    zkgroup::serialize(&request)
}

#[bridge_fn]
fn BackupAuthCredentialRequest_CheckValidContents(
    request_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<BackupAuthCredentialRequest>(request_bytes)
}

#[bridge_fn]
fn BackupAuthCredentialRequest_IssueDeterministic(
    request_bytes: &[u8],
    redemption_time: Timestamp,
    backup_level: AsType<BackupLevel, u8>,
    credential_type: AsType<BackupCredentialType, u8>,
    params_bytes: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Vec<u8> {
    let request = bincode::deserialize::<BackupAuthCredentialRequest>(request_bytes)
        .expect("should have been parsed previously");
    let params = bincode::deserialize::<GenericServerSecretParams>(params_bytes)
        .expect("should have been parsed previously");

    let response = request.issue(
        redemption_time,
        backup_level.into_inner(),
        credential_type.into_inner(),
        &params,
        *randomness,
    );
    zkgroup::serialize(&response)
}

#[bridge_fn]
fn BackupAuthCredentialResponse_CheckValidContents(
    response_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<BackupAuthCredentialResponse>(response_bytes)
}

#[bridge_fn]
fn BackupAuthCredentialRequestContext_ReceiveResponse(
    context_bytes: &[u8],
    response_bytes: &[u8],
    expected_redemption_time: Timestamp,
    params_bytes: &[u8],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let context = bincode::deserialize::<BackupAuthCredentialRequestContext>(context_bytes)
        .expect("should have been parsed previously");
    let response = bincode::deserialize::<BackupAuthCredentialResponse>(response_bytes)
        .expect("should have been parsed previously");
    let params = bincode::deserialize::<GenericServerPublicParams>(params_bytes)
        .expect("should have been parsed previously");

    let credential = context.receive(response, &params, expected_redemption_time)?;
    Ok(zkgroup::serialize(&credential))
}

#[bridge_fn]
fn BackupAuthCredential_CheckValidContents(
    params_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<BackupAuthCredential>(params_bytes)
}

#[bridge_fn]
fn BackupAuthCredential_GetBackupId(credential_bytes: &[u8]) -> [u8; 16] {
    let credential = bincode::deserialize::<BackupAuthCredential>(credential_bytes)
        .expect("should have been parsed previously");
    credential.backup_id().0
}

#[bridge_fn]
fn BackupAuthCredential_GetBackupLevel(credential_bytes: &[u8]) -> u8 {
    let credential = bincode::deserialize::<BackupAuthCredential>(credential_bytes)
        .expect("should have been parsed previously");
    credential.backup_level() as u8
}

#[bridge_fn]
fn BackupAuthCredential_GetType(credential_bytes: &[u8]) -> u8 {
    let credential = bincode::deserialize::<BackupAuthCredential>(credential_bytes)
        .expect("should have been parsed previously");
    credential.credential_type() as u8
}

#[bridge_fn]
fn BackupAuthCredential_PresentDeterministic(
    credential_bytes: &[u8],
    server_params_bytes: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Result<Vec<u8>, ZkGroupVerificationFailure> {
    let credential = bincode::deserialize::<BackupAuthCredential>(credential_bytes)
        .expect("should have been parsed previously");
    let server_params = bincode::deserialize::<GenericServerPublicParams>(server_params_bytes)
        .expect("should have been parsed previously");

    let presentation = credential.present(&server_params, *randomness);
    Ok(zkgroup::serialize(&presentation))
}

#[bridge_fn]
fn BackupAuthCredentialPresentation_CheckValidContents(
    presentation_bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<BackupAuthCredentialPresentation>(presentation_bytes)
}

#[bridge_fn]
fn BackupAuthCredentialPresentation_Verify(
    presentation_bytes: &[u8],
    now: Timestamp,
    server_params_bytes: &[u8],
) -> Result<(), ZkGroupVerificationFailure> {
    let presentation = bincode::deserialize::<BackupAuthCredentialPresentation>(presentation_bytes)
        .expect("should have been parsed previously");
    let server_params = bincode::deserialize::<GenericServerSecretParams>(server_params_bytes)
        .expect("should have been parsed previously");

    presentation.verify(now, &server_params)
}

#[bridge_fn(ffi = false)]
fn BackupAuthCredentialPresentation_GetBackupId(presentation_bytes: &[u8]) -> [u8; 16] {
    let presentation = bincode::deserialize::<BackupAuthCredentialPresentation>(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.backup_id().0
}

#[bridge_fn(ffi = false)]
fn BackupAuthCredentialPresentation_GetBackupLevel(presentation_bytes: &[u8]) -> u8 {
    let presentation = bincode::deserialize::<BackupAuthCredentialPresentation>(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.backup_level() as u8
}

#[bridge_fn(ffi = false)]
fn BackupAuthCredentialPresentation_GetType(presentation_bytes: &[u8]) -> u8 {
    let presentation = bincode::deserialize::<BackupAuthCredentialPresentation>(presentation_bytes)
        .expect("should have been parsed previously");
    presentation.credential_type() as u8
}

#[bridge_fn]
fn GroupSendDerivedKeyPair_CheckValidContents(
    bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GroupSendDerivedKeyPair>(bytes)
}

#[bridge_fn]
fn GroupSendDerivedKeyPair_ForExpiration(
    expiration: Timestamp,
    server_params: &ServerSecretParams,
) -> Vec<u8> {
    zkgroup::serialize(&GroupSendDerivedKeyPair::for_expiration(
        expiration,
        server_params,
    ))
}

#[bridge_fn]
fn GroupSendEndorsementsResponse_CheckValidContents(
    bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GroupSendEndorsementsResponse>(bytes)
}

#[bridge_fn]
fn GroupSendEndorsementsResponse_IssueDeterministic(
    concatenated_group_member_ciphertexts: &[u8],
    key_pair: &[u8],
    randomness: &[u8; RANDOMNESS_LEN],
) -> Vec<u8> {
    assert!(concatenated_group_member_ciphertexts.len() % UUID_CIPHERTEXT_LEN == 0);
    let user_id_ciphertexts = concatenated_group_member_ciphertexts
        .chunks_exact(UUID_CIPHERTEXT_LEN)
        .map(|serialized| {
            zkgroup::deserialize::<UuidCiphertext>(serialized)
                .expect("should have been parsed previously")
        });

    let key_pair = zkgroup::deserialize::<GroupSendDerivedKeyPair>(key_pair)
        .expect("should have been parsed previously");

    zkgroup::serialize(&GroupSendEndorsementsResponse::issue(
        user_id_ciphertexts,
        &key_pair,
        *randomness,
    ))
}

#[bridge_fn]
fn GroupSendEndorsementsResponse_GetExpiration(response_bytes: &[u8]) -> Timestamp {
    let response = zkgroup::deserialize::<GroupSendEndorsementsResponse>(response_bytes)
        .expect("should have been parsed previously");
    response.expiration()
}

#[bridge_fn]
fn GroupSendEndorsementsResponse_ReceiveAndCombineWithServiceIds(
    response_bytes: &[u8],
    group_members: ServiceIdSequence<'_>,
    local_user: ServiceId,
    now: Timestamp,
    group_params: Serialized<GroupSecretParams>,
    server_params: &ServerPublicParams,
) -> Result<Box<[Vec<u8>]>, ZkGroupVerificationFailure> {
    let response = zkgroup::deserialize::<GroupSendEndorsementsResponse>(response_bytes)
        .expect("should have been parsed previously");

    let local_user_index = group_members
        .into_iter()
        .position(|next| next == local_user)
        .expect("local user not included in member list");

    let endorsements =
        response.receive_with_service_ids(group_members, now, &group_params, server_params)?;
    let combined_endorsement = GroupSendEndorsement::combine(
        endorsements[..local_user_index]
            .iter()
            .chain(&endorsements[local_user_index + 1..])
            .map(|received| received.decompressed),
    );
    Ok(endorsements
        .iter()
        .map(|received| received.compressed)
        .chain([combined_endorsement.compress()])
        .map(|e| zkgroup::serialize(&e))
        .collect())
}

#[bridge_fn]
fn GroupSendEndorsementsResponse_ReceiveAndCombineWithCiphertexts(
    response_bytes: &[u8],
    concatenated_group_member_ciphertexts: &[u8],
    local_user_ciphertext: &[u8],
    now: Timestamp,
    server_params: &ServerPublicParams,
) -> Result<Box<[Vec<u8>]>, ZkGroupVerificationFailure> {
    let response = zkgroup::deserialize::<GroupSendEndorsementsResponse>(response_bytes)
        .expect("should have been parsed previously");

    assert!(concatenated_group_member_ciphertexts.len() % UUID_CIPHERTEXT_LEN == 0);
    let local_user_index = concatenated_group_member_ciphertexts
        .chunks_exact(UUID_CIPHERTEXT_LEN)
        .position(|serialized| serialized == local_user_ciphertext)
        .expect("local user not included in member list");

    let user_id_ciphertexts = concatenated_group_member_ciphertexts
        .chunks_exact(UUID_CIPHERTEXT_LEN)
        .map(|serialized| {
            zkgroup::deserialize::<UuidCiphertext>(serialized)
                .expect("should have been parsed previously")
        });

    let endorsements =
        response.receive_with_ciphertexts(user_id_ciphertexts, now, server_params)?;
    let combined_endorsement = GroupSendEndorsement::combine(
        endorsements[..local_user_index]
            .iter()
            .chain(&endorsements[local_user_index + 1..])
            .map(|received| received.decompressed),
    );
    Ok(endorsements
        .iter()
        .map(|received| received.compressed)
        .chain([combined_endorsement.compress()])
        .map(|e| zkgroup::serialize(&e))
        .collect())
}

#[bridge_fn]
fn GroupSendEndorsement_CheckValidContents(
    bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GroupSendEndorsement>(bytes)
}

#[bridge_fn]
fn GroupSendEndorsement_Combine(endorsements: Vec<&[u8]>) -> Vec<u8> {
    let combined = GroupSendEndorsement::combine(
        endorsements
            .into_iter()
            .map(|next| zkgroup::deserialize(next).expect("should have been parsed previously")),
    );
    zkgroup::serialize(&combined)
}

#[bridge_fn]
fn GroupSendEndorsement_Remove(endorsement: &[u8], to_remove: &[u8]) -> Vec<u8> {
    let endorsement = zkgroup::deserialize::<GroupSendEndorsement>(endorsement)
        .expect("should have been parsed previously");
    let to_remove = zkgroup::deserialize::<GroupSendEndorsement>(to_remove)
        .expect("should have been parsed previously");

    zkgroup::serialize(&endorsement.remove(&to_remove))
}

#[bridge_fn]
fn GroupSendEndorsement_ToToken(
    endorsement: &[u8],
    group_params: Serialized<GroupSecretParams>,
) -> Vec<u8> {
    let endorsement = zkgroup::deserialize::<GroupSendEndorsement>(endorsement)
        .expect("should have been parsed previously");
    zkgroup::serialize(&endorsement.to_token(&group_params))
}

#[bridge_fn]
fn GroupSendToken_CheckValidContents(bytes: &[u8]) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GroupSendToken>(bytes)
}

#[bridge_fn]
fn GroupSendToken_ToFullToken(token: &[u8], expiration: Timestamp) -> Vec<u8> {
    let token =
        zkgroup::deserialize::<GroupSendToken>(token).expect("should have been parsed previously");
    zkgroup::serialize(&token.into_full_token(expiration))
}

#[bridge_fn]
fn GroupSendFullToken_CheckValidContents(
    bytes: &[u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    validate_serialization::<GroupSendFullToken>(bytes)
}

#[bridge_fn]
fn GroupSendFullToken_GetExpiration(token: &[u8]) -> Timestamp {
    let token = zkgroup::deserialize::<GroupSendFullToken>(token)
        .expect("should have been parsed previously");
    token.expiration()
}

#[bridge_fn]
fn GroupSendFullToken_Verify(
    token: &[u8],
    user_ids: ServiceIdSequence<'_>,
    now: Timestamp,
    key_pair: &[u8],
) -> Result<(), ZkGroupVerificationFailure> {
    let token = zkgroup::deserialize::<GroupSendFullToken>(token)
        .expect("should have been parsed previously");
    let key_pair = zkgroup::deserialize::<GroupSendDerivedKeyPair>(key_pair)
        .expect("should have been parsed previously");
    token.verify(user_ids, now, &key_pair)
}
