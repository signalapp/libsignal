//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthProfilesService: Sendable {
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
