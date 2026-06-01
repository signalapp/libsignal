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

public struct BackupCdnCredentials: Sendable {
    public var headers: [String: String]
    public init(headers: [String: String]) {
        self.headers = headers
    }
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

    @available(*, deprecated, message: "requires every connection to support H2")
    func setBackupPublicKey(auth: BackupAuth, rngForTesting: Int64) async throws
    @available(*, deprecated, message: "requires every connection to support H2")
    func getBackupCdnCredentials(
        auth: BackupAuth,
        cdn: Int32,
        rngForTesting: Int64
    ) async throws -> BackupCdnCredentials
    @available(*, deprecated, message: "requires every connection to support H2")
    func getBackupSvrBCredentials(auth: BackupAuth, rngForTesting: Int64) async throws -> Auth
    @available(*, deprecated, message: "requires every connection to support H2")
    func refreshBackup(auth: BackupAuth, rngForTesting: Int64) async throws
    @available(*, deprecated, message: "requires every connection to support H2")
    func backupDeleteAll(auth: BackupAuth, rngForTesting: Int64) async throws
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

    @available(*, deprecated, message: "requires every connection to support H2")
    func setBackupPublicKey(auth: BackupAuth, rngForTesting: Int64) async throws {
        try await NativeNice
            .UnauthenticatedChatConnection_backup_set_public_key(
                asyncContext: self.tokioAsyncContext,
                chat: self,
                credential: auth.credential,
                serverKeys: auth.serverKeys,
                signingKey: auth.signingKey,
                rng: rngForTesting
            )
    }

    @available(*, deprecated, message: "requires every connection to support H2")
    func getBackupCdnCredentials(
        auth: BackupAuth,
        cdn: Int32,
        rngForTesting: Int64
    ) async throws -> BackupCdnCredentials {
        try await NativeNice
            .UnauthenticatedChatConnection_backup_get_cdn_credentials(
                asyncContext: self.tokioAsyncContext,
                chat: self,
                credential: auth.credential,
                serverKeys: auth.serverKeys,
                signingKey: auth.signingKey,
                cdn: cdn,
                rng: rngForTesting
            )
    }

    @available(*, deprecated, message: "requires every connection to support H2")
    func getBackupSvrBCredentials(auth: BackupAuth, rngForTesting: Int64) async throws -> Auth {
        let (username, password) = try await NativeNice.UnauthenticatedChatConnection_backup_get_svrb_credentials(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            credential: auth.credential,
            serverKeys: auth.serverKeys,
            signingKey: auth.signingKey,
            rng: rngForTesting
        )
        return Auth(username: username, password: password)
    }

    @available(*, deprecated, message: "requires every connection to support H2")
    func refreshBackup(auth: BackupAuth, rngForTesting: Int64) async throws {
        try await NativeNice
            .UnauthenticatedChatConnection_backup_refresh(
                asyncContext: self.tokioAsyncContext,
                chat: self,
                credential: auth.credential,
                serverKeys: auth.serverKeys,
                signingKey: auth.signingKey,
                rng: rngForTesting
            )
    }

    @available(*, deprecated, message: "requires every connection to support H2")
    func backupDeleteAll(auth: BackupAuth, rngForTesting: Int64) async throws {
        try await NativeNice
            .UnauthenticatedChatConnection_backup_delete_all(
                asyncContext: self.tokioAsyncContext,
                chat: self,
                credential: auth.credential,
                serverKeys: auth.serverKeys,
                signingKey: auth.signingKey,
                rng: rngForTesting
            )
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthBackupsService> {
    public static var backups: Self { .init() }
}
extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthBackupsServiceImpl> {
    internal static var backupsImpl: Self { .init() }
}
