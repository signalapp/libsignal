//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthProfilesService: Sendable {
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
