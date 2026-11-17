//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthProfilesService: Sendable {
    /// Retrieves profile data.
    ///
    /// Callers with an unidentified access key for the account should use the unauth version,
    /// instead.
    ///
    /// - Returns: nil if the provided etag is up-to-date
    /// - Throws:
    ///   - ``SignalError/profileNotFound(_:)`` if the profile (version) could not be found
    ///   - ``SignalError/profileCantBeDecoded(_:)`` if the profile failed to decode (e.g. due to encryption or validation errors)
    ///   - the standard Signal network errors
    func getProfile(
        aci: Aci,
        profileKey: ProfileKey,
        etag: ProfileEtag?,
    ) async throws -> FetchedProfile?
    /// Set the profile for the current account.
    ///
    /// Note that if an older client (not yet using libsignal to set profiles) sets a v1 profile,
    /// this will clear out the v2 profile, and expectedCurrentDataHash should be nil in
    /// these cases.
    ///
    /// The easiest way to obtain the correct expectedCurrentDataHash is to invoke
    /// getProfile() on the current account. The resulting FetchedProfile’s v2DataHash
    /// will be the correct value (regardless of whether it’s null or not) to pass to the
    /// expectedCurrentDataHash argument of this function.
    ///
    /// - Parameters:
    ///   - aci: the ACI of the current account
    ///   - profileKey: the profile key to use when setting the profile. This can be the same, or different from the current profile key
    ///   - expectedCurrentDataHash: must exactly match the server’s view of the current profile v2 data hash. When changing to a new profile key, expectedCurrentDataHash must be null. If this is the first v2 profile for this profile key, then expectedCurrentDataHash must be null. Otherwise, expectedCurrentDataHash must be the result of the last successful setProfile() invocation from across all devices on the account.
    ///   - expectedCurrentProfileKeyVersion: must be the current profile key version of the account (or null if there is no current version). In case of mismatch, the resulting error will contain the current profile key version, which may be passed into this parameter on a subsequent request.
    /// - Throws:
    ///   - ``SignalError/setProfileErrorInvalidProfile(profileValidationError:message:)`` if the provided profile isn't valid
    ///   - ``SignalError/setProfileErrorExpectedDataWriteConflict(_:)`` if the current data hash did not match the request's expectation, indicating  another device on the account may have written an update the caller does not know about.
    ///   - ``SignalError/setProfileErrorExpectedVersionWriteConflict(currentProfileVersion:message:)`` if the current version did not match the request's expectation, indicating another device on the account may have created a new version the caller does not know about.
    ///   - ``SignalError/setProfileErrorPaymentsForbiddenInRegion(_:)`` if payments  are not permitted in the account's region, based on its phone number or the caller's IP address if the account does not have a phone number. The request should be retried without paymentAddress.
    ///   - ``SignalError/invalidArgument(_:)`` if `profile.phoneNumberSharing` is `nil`
    ///   - the standard Signal network errors
    func setProfile(
        aci: Aci,
        profileKey: ProfileKey,
        profile: Profile,
        expectedCurrentDataHash: ProfileDataHash?,
        expectedCurrentProfileKeyVersion: ProfileKeyVersion?,
    ) async throws -> ProfileDataHash
    /// Returns an anonymous credential that may be presented with avatar operations in
    /// UnauthProfilesService
    ///
    /// - Parameters:
    ///   - aci: the ACI of the current account
    ///   - keyPair: the ``ZkCredentialKeyPair`` of the current account
    ///   - rotationId: the ``ZkCredentialKeyRotationId`` from when the `keyPair` was set
    ///   - serverPublicParams: the server's zk parameters
    /// - Throws:
    ///   - ``SignalError/accountMissingZkCredentialKey(_:)`` if the account doesn't have a ZkCredentialKeyPair set
    ///   - the standard Signal network errors
    func getAvatarCredential(
        aci: Aci,
        keyPair: ZkCredentialKeyPair,
        rotationId: ZkCredentialKeyRotationId,
        serverPublicParams: GenericServerPublicParams,
    ) async throws -> AvatarUploadCredential
    /// Returns a form to upload a legacy (v1) avatar.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func getAvatarUploadFormLegacy(
        aci: Aci,
        profileKey: ProfileKey,
    ) async throws -> S3UploadForm
}

extension AuthenticatedChatConnection: AuthProfilesService {

    public func getProfile(aci: Aci, profileKey: ProfileKey, etag: Data?, ) async throws -> FetchedProfile? {
        return try await NativeNice.AuthenticatedChatConnection_get_profile(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            aci: aci,
            profileKey: profileKey,
            etag: etag,
        )
    }

    public func setProfile(
        aci: Aci,
        profileKey: ProfileKey,
        profile: Profile,
        expectedCurrentDataHash: ProfileDataHash?,
        expectedCurrentProfileKeyVersion: ProfileKeyVersion?,
    ) async throws -> ProfileDataHash {
        return try await self.setProfileImpl(
            aci: aci,
            profileKey: profileKey,
            profile: profile,
            expectedCurrentDataHash: expectedCurrentDataHash,
            expectedCurrentProfileKeyVersion: expectedCurrentProfileKeyVersion,
        )
    }

    public func getAvatarCredential(
        aci: Aci,
        keyPair: ZkCredentialKeyPair,
        rotationId: Int64,
        serverPublicParams: GenericServerPublicParams,
    ) async throws -> AvatarUploadCredential {
        return try await self.getAvatarCredentialImpl(
            aci: aci,
            keyPair: keyPair,
            rotationId: rotationId,
            serverPublicParams: serverPublicParams
        )
    }

    public func getAvatarUploadFormLegacy(aci: Aci, profileKey: ProfileKey) async throws -> S3UploadForm {
        return try await NativeNice.AuthenticatedChatConnection_get_avatar_upload_form_legacy(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            aci: aci,
            profileKey: profileKey,
        )
    }

}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthProfilesService> {
    public static var profiles: Self { .init() }
}

extension AuthenticatedChatConnection {
    internal func setProfileImpl(
        rng: Int64 = -1,
        aci: Aci,
        profileKey: ProfileKey,
        profile: Profile,
        expectedCurrentDataHash: Data?,
        expectedCurrentProfileKeyVersion: ProfileKeyVersion?,
    ) async throws -> Data {
        return try await NativeNice.AuthenticatedChatConnection_set_profile(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            rng: rng,
            aci: aci,
            profileKey: profileKey,
            profile: profile,
            expectedCurrentDataHash: expectedCurrentDataHash,
            expectedCurrentProfileKeyVersion: expectedCurrentProfileKeyVersion,
        )
    }
    internal func getAvatarCredentialImpl(
        aci: Aci,
        keyPair: ZkCredentialKeyPair,
        rotationId: ZkCredentialKeyRotationId,
        serverPublicParams: GenericServerPublicParams,
        currentTimeSeconds: Date = Date(),
        rng: Int64 = -1,
    ) async throws -> AvatarUploadCredential {
        return try await NativeNice.AuthenticatedChatConnection_get_avatar_credential(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            aci: aci,
            keyPair: keyPair,
            rotationId: rotationId,
            serverPublicParams: serverPublicParams,
            currentTimeSeconds: Int64(currentTimeSeconds.timeIntervalSince1970),
            rng: rng,
        )
    }
}
