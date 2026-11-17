//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public enum UnauthProfileAuthorization: Sendable {
    /// The unauthenticated access key
    case accessKey(Data)
    case groupSend(GroupSendFullToken)
}

public protocol UnauthProfilesService: Sendable {
    /// Retrieves profile data.
    ///
    /// - Returns: nil if the provided etag is up-to-date
    /// - Throws:
    ///   - ``SignalError/profileNotFound(_:)`` if the profile (version) could not be found
    ///   - ``SignalError/profileCantBeDecoded(_:)`` if the profile failed to decode (e.g. due to encryption or validation errors)
    ///   - ``SignalError/requestUnauthorized(_:)`` if the authorization fails
    ///   - the standard Signal network errors
    func getProfile(
        aci: Aci,
        profileKey: ProfileKey,
        auth: UnauthProfileAuthorization,
        etag: ProfileEtag?,
        avatarCdnUrlValidationConfig: AvatarCdnUrlValidationConfig,
    ) async throws -> FetchedProfile?
    /// Returns a credential to upload a v2 avatar.
    ///
    /// After uploading the avatar, the client
    /// must call SetProfile with the new avatar URL in the encrypted data.
    ///
    /// Because avatars are uploaded anonymously, they have an expiration equal to the
    /// idle account expiration. Clients must periodically (recommended: every 90 days)
    /// call extendAvatarTtl() to extend the TTL.
    ///
    /// NOTE: any existing avatar associated with this credential will be deleted immediately
    /// Clients should not be uploading v2 avatars until after the v1->v2 avatar transition.
    ///
    /// - Parameters:
    ///   - uploadLength: Uploads will be limited to uploadLength bytes. It must be in the range [1, 10485760] (10 MiB), else the server will reject the upload.
    /// - Throws:
    ///   - ``SignalError/invalidAvatarUploadCredentialPresentation(_:)`` if the credential is invalid
    ///   - the standard Signal network errors
    func getAvatarUploadForm(
        credential: AvatarUploadCredentialPresentation,
        uploadLength: Int32,
    ) async throws -> S3UploadForm
    /// Delete the account’s avatar from the CDN.
    ///
    /// Clients must also call setProfile() to remove the avatar URL from the profile data.
    ///
    /// - Throws:
    ///   - ``SignalError/invalidAvatarUploadCredentialPresentation(_:)`` if the credential is invalid
    ///   - the standard Signal network errors
    func deleteAvatar(
        credential: AvatarUploadCredentialPresentation,
    ) async throws
    /// Extend the TTL of a v2 avatar
    ///
    /// The server doesn’t know which v2 avatars correspond to which Signal account. As a result,
    /// v2 avatars expire after a time. To keep an account’s avatar from expiring, clients must
    /// call extend_avatar_ttl() on a regular basis (recommended: every 90 days).
    ///
    /// It is safe to keep calling this during the v1->v2 transition. v1 avatars will just be
    /// treated as "not found."
    ///
    /// Returns either the CdnUrl of the current v2 avtar, or nil, if none is set.
    ///
    /// - Throws:
    ///   - ``SignalError/invalidAvatarUploadCredentialPresentation(_:)`` if the credential is invalid
    ///   - the standard Signal network errors
    func extendAvatarTtl(
        credential: AvatarUploadCredentialPresentation,
    ) async throws -> CdnUrl?

    /// Does an account with the given ACI or PNI exist?
    ///
    /// Throws only if the request can't be completed.
    func accountExists(_ account: ServiceId) async throws -> Bool

    /// Fetches a profile key credential using the given request context.
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if the profile key does not match the access key
    ///     stored on the server.
    ///   - ``SignalError/profileNotFound(_:)`` if the account in question does not exist or does not
    ///     have a profile (possible if they have not finished setting up their account).
    ///     Check ``accountExists(_:)`` if you need to distinguish between these possibilities.
    ///   - the standard Signal network errors
    func getProfileKeyCredential(
        requestContext: ProfileKeyCredentialRequestContext,
        serverParams: ServerPublicParams
    ) async throws -> ExpiringProfileKeyCredential
}

extension UnauthenticatedChatConnection: UnauthProfilesService {

    public func getProfile(
        aci: Aci,
        profileKey: ProfileKey,
        auth: UnauthProfileAuthorization,
        etag: ProfileEtag?,
        avatarCdnUrlValidationConfig: AvatarCdnUrlValidationConfig,
    ) async throws -> FetchedProfile? {
        return try await NativeNice.UnauthenticatedChatConnection_get_profile(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            aci: aci,
            profileKey: profileKey,
            auth: auth,
            etag: etag,
            avatarCdnConfig: avatarCdnUrlValidationConfig,
        )
    }

    public func getAvatarUploadForm(
        credential: AvatarUploadCredentialPresentation,
        uploadLength: Int32,
    ) async throws -> S3UploadForm {
        return try await NativeNice.UnauthenticatedChatConnection_get_avatar_upload_form(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            credential: credential,
            uploadLength: uploadLength,
        )
    }

    public func deleteAvatar(credential: AvatarUploadCredentialPresentation) async throws {
        return try await NativeNice.UnauthenticatedChatConnection_delete_avatar(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            credential: credential,
        )
    }

    public func extendAvatarTtl(credential: AvatarUploadCredentialPresentation) async throws -> CdnUrl? {
        return try await NativeNice.UnauthenticatedChatConnection_extend_avatar_ttl(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            credential: credential,
        )
    }

    public func accountExists(_ account: ServiceId) async throws -> Bool {
        return try await NativeNice.UnauthenticatedChatConnection_account_exists(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            account: account
        )
    }

    public func getProfileKeyCredential(
        requestContext: ProfileKeyCredentialRequestContext,
        serverParams: ServerPublicParams
    ) async throws -> ExpiringProfileKeyCredential {
        return try await NativeNice.UnauthenticatedChatConnection_get_profile_key_credential(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            profileKeyRequestContext: requestContext,
            serverParams: serverParams
        )
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthProfilesService> {
    public static var profiles: Self { .init() }
}
