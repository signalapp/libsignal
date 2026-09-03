//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// The output of ``AuthStickersService/getStickerUploadForms(numberOfStickers:)``.
public struct GetStickerUploadFormsResponse: Equatable, Sendable {
    /// A randomly-generated ID for the new sticker pack.
    public var packId: String
    /// An upload form clients must use to upload a manifest for the sticker pack.
    public var manifestUploadForm: S3UploadForm
    /// Upload forms for individual stickers within the sticker pack.
    public var stickerUploadForms: [S3UploadForm]

    public init(packId: String, manifestUploadForm: S3UploadForm, stickerUploadForms: [S3UploadForm]) {
        self.packId = packId
        self.manifestUploadForm = manifestUploadForm
        self.stickerUploadForms = stickerUploadForms
    }
}

public protocol AuthStickersService: Sendable {
    /// Retrieve a set of upload forms that can be used to upload a sticker pack.
    ///
    /// A successful response is guaranteed to have the requested number of sticker upload forms.
    ///
    /// - Parameters:
    ///   - numberOfStickers: Must be between 1 and 201 (inclusive).
    /// - Throws:
    ///   - the standard Signal network errors
    func getStickerUploadForms(numberOfStickers: Int) async throws -> GetStickerUploadFormsResponse
}

extension AuthenticatedChatConnection: AuthStickersService {
    public func getStickerUploadForms(numberOfStickers: Int) async throws -> GetStickerUploadFormsResponse {
        return try await NativeNice.AuthenticatedChatConnection_get_sticker_upload_forms(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            numberOfStickers: Int32(numberOfStickers),
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthStickersService> {
    public static var stickers: Self { .init() }
}
