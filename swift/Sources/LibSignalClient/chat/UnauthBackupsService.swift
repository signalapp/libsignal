//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public struct BackupAuth: Sendable {
    public init(credential: BackupAuthCredential, serverKeys: GenericServerPublicParams, signingKey: PrivateKey) {
        self.credential = credential
        self.serverKeys = serverKeys
        self.signingKey = signingKey
    }

    public let credential: BackupAuthCredential
    public let serverKeys: GenericServerPublicParams
    public let signingKey: PrivateKey
}

public protocol UnauthBackupsService: Sendable {
    /// Get a messages backup upload form
    ///
    /// - Throws:
    ///   - ``SignalError/uploadTooLarge(_:)`` if ``uploadSize`` is too large
    ///   - ``SignalError/requestUnauthorized(_:)`` if there are authorization issues
    ///   - the standard Signal network errors
    func getUploadForm(
        auth: BackupAuth,
        uploadSize: UInt64,
    ) async throws -> UploadForm

    /// Get an attachment backup upload form
    ///
    /// - Throws:
    ///   - ``SignalError/uploadTooLarge(_:)`` if ``uploadSize`` is too large
    ///   - ``SignalError/requestUnauthorized(_:)`` if there are authorization issues
    ///   - the standard Signal network errors
    func getMediaUploadForm(
        auth: BackupAuth,
        uploadSize: UInt64,
    ) async throws -> UploadForm
}

extension UnauthenticatedChatConnection: UnauthBackupsService {
    public func getUploadForm(
        auth: BackupAuth,
        uploadSize: UInt64
    ) async throws -> UploadForm {
        return try await self.getUploadFormImpl(
            auth: auth,
            uploadSize: uploadSize,
            rngForTesting: -1,
        )
    }
    public func getMediaUploadForm(
        auth: BackupAuth,
        uploadSize: UInt64
    ) async throws -> UploadForm {
        return try await self.getMediaUploadFormImpl(
            auth: auth,
            uploadSize: uploadSize,
            rngForTesting: -1,
        )
    }
}

internal protocol UnauthBackupsServiceImpl: Sendable {
    func getUploadFormImpl(
        auth: BackupAuth,
        uploadSize: UInt64,
        rngForTesting: Int64,
    ) async throws -> UploadForm
    func getMediaUploadFormImpl(
        auth: BackupAuth,
        uploadSize: UInt64,
        rngForTesting: Int64,
    ) async throws -> UploadForm
}

extension UnauthenticatedChatConnection: UnauthBackupsServiceImpl {
    func getUploadFormImpl(
        auth: BackupAuth,
        uploadSize: UInt64,
        rngForTesting: Int64,
    ) async throws -> UploadForm {
        let credential = auth.credential.serialize()
        let serverKeys = auth.serverKeys.serialize()
        return try UploadForm(
            consuming: try await self.tokioAsyncContext.invokeAsyncFunction {
                promise,
                tokioAsyncContext in
                withNativeHandle { chatService in
                    credential.withUnsafeBorrowedBuffer { credential in
                        serverKeys.withUnsafeBorrowedBuffer { serverKeys in
                            auth.signingKey.withNativeHandle { signingKey in
                                signal_unauthenticated_chat_connection_backup_get_upload_form(
                                    promise,
                                    tokioAsyncContext.const(),
                                    chatService.const(),
                                    credential,
                                    serverKeys,
                                    signingKey.const(),
                                    uploadSize,
                                    rngForTesting,
                                )
                            }
                        }
                    }
                }
            }
        )
    }
    func getMediaUploadFormImpl(
        auth: BackupAuth,
        uploadSize: UInt64,
        rngForTesting: Int64,
    ) async throws -> UploadForm {
        let credential = auth.credential.serialize()
        let serverKeys = auth.serverKeys.serialize()
        return try UploadForm(
            consuming: try await self.tokioAsyncContext.invokeAsyncFunction {
                promise,
                tokioAsyncContext in
                withNativeHandle { chatService in
                    credential.withUnsafeBorrowedBuffer { credential in
                        serverKeys.withUnsafeBorrowedBuffer { serverKeys in
                            auth.signingKey.withNativeHandle { signingKey in
                                signal_unauthenticated_chat_connection_backup_get_media_upload_form(
                                    promise,
                                    tokioAsyncContext.const(),
                                    chatService.const(),
                                    credential,
                                    serverKeys,
                                    signingKey.const(),
                                    uploadSize,
                                    rngForTesting,
                                )
                            }
                        }
                    }
                }
            }
        )
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthBackupsService> {
    public static var backups: Self { .init() }
}
extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthBackupsServiceImpl> {
    internal static var backupsImpl: Self { .init() }
}
