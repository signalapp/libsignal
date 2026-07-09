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

    /// Sets the messages or media backup key based on `auth`.
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if there are authorization issues; since the key
    ///     is being updated, this suggests the credential in particular is invalid
    ///   - the standard Signal network errors
    func setBackupPublicKey(auth: BackupAuth) async throws

    /// Fetches the credentials necessary to read from the given backup CDN.
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if there are authorization issues
    ///   - the standard Signal network errors
    func getBackupCdnCredentials(auth: BackupAuth, cdn: Int32) async throws -> BackupCdnCredentials

    /// Fetches the credentials for connecting to SVR-B (a username/password pair).
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if there are authorization issues
    ///   - the standard Signal network errors
    func getBackupSvrBCredentials(auth: BackupAuth) async throws -> Auth

    /// Indicates that the backup is still active.
    ///
    /// Clients must periodically upload new backups or perform a refresh. If a backup has not been
    /// active for 30 days, it may be deleted.
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if there are authorization issues
    ///   - the standard Signal network errors
    func refreshBackup(auth: BackupAuth) async throws

    /// Deletes all backup metadata, objects, and stored public key.
    ///
    /// To use backups again, a public key must be resupplied.
    ///
    /// - Throws:
    ///   - ``SignalError/requestUnauthorized(_:)`` if there are authorization issues
    ///   - the standard Signal network errors
    func backupDeleteAll(auth: BackupAuth) async throws

    /// Copy and re-encrypt media from the attachments CDN into the backup CDN.
    ///
    /// The original, already encrypted, attachments will be encrypted with the
    /// provided key material before being copied. On retries, a particular destination media ID
    /// must not be reused with a different source media key or different encryption parameters.
    ///
    /// The copy operation is not atomic and responses will be returned as copy operations complete
    /// with detailed information about the outcome. If an error is encountered, not all requests
    /// may be reflected in the responses. However, there is no need to retry the items that did
    /// receive a response.
    ///
    /// The stream may be terminated at any time with the standard Signal network errors.
    /// In addition, the stream may immediately terminate with ``SignalError/requestUnauthorized(_:)``
    /// if there are authorization issues.
    ///
    /// The stream can be manually cancelled to free resources immediately (rather than waiting for
    /// deinitialization). If the stream is cancelled and then read from again, it may produce a
    /// timeout error. It is not required to cancel the stream even if it is not read to completion.
    func copyBackupMedia(
        auth: BackupAuth,
        items: some Sequence<CopyBackupMediaItem>
    ) throws -> ColdAsyncStream<CopyBackupMediaOutcome>
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

    public func setBackupPublicKey(auth: BackupAuth) async throws {
        try await self.setBackupPublicKey(auth: auth, rngForTesting: -1)
    }
    public func getBackupCdnCredentials(auth: BackupAuth, cdn: Int32) async throws -> BackupCdnCredentials {
        return try await self.getBackupCdnCredentials(auth: auth, cdn: cdn, rngForTesting: -1)
    }
    public func getBackupSvrBCredentials(auth: BackupAuth) async throws -> Auth {
        return try await self.getBackupSvrBCredentials(auth: auth, rngForTesting: -1)
    }
    public func refreshBackup(auth: BackupAuth) async throws {
        try await self.refreshBackup(auth: auth, rngForTesting: -1)
    }
    public func backupDeleteAll(auth: BackupAuth) async throws {
        try await self.backupDeleteAll(auth: auth, rngForTesting: -1)
    }

    public func copyBackupMedia(
        auth: BackupAuth,
        items: some Sequence<CopyBackupMediaItem>
    ) throws -> ColdAsyncStream<CopyBackupMediaOutcome> {
        try self.copyBackupMedia(auth: auth, items: items, rngForTesting: -1)
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

    func setBackupPublicKey(auth: BackupAuth, rngForTesting: Int64) async throws
    func getBackupCdnCredentials(
        auth: BackupAuth,
        cdn: Int32,
        rngForTesting: Int64
    ) async throws -> BackupCdnCredentials
    func getBackupSvrBCredentials(auth: BackupAuth, rngForTesting: Int64) async throws -> Auth
    func refreshBackup(auth: BackupAuth, rngForTesting: Int64) async throws
    func backupDeleteAll(auth: BackupAuth, rngForTesting: Int64) async throws

    func copyBackupMedia(
        auth: BackupAuth,
        items: some Sequence<CopyBackupMediaItem>,
        rngForTesting: Int64
    ) throws -> ColdAsyncStream<CopyBackupMediaOutcome>
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

    func copyBackupMedia(
        auth: BackupAuth,
        items: some Sequence<CopyBackupMediaItem>,
        rngForTesting: Int64
    ) throws -> ColdAsyncStream<CopyBackupMediaOutcome> {
        let stream = try NativeNice.UnauthenticatedChatConnection_backup_copy_media(
            chat: self,
            credential: auth.credential,
            serverKeys: auth.serverKeys,
            signingKey: auth.signingKey,
            items: items.map { $0.toBridge() },
            rng: rngForTesting
        )

        return ColdAsyncStream(
            asyncContext: self.tokioAsyncContext,
            stream: stream,
            pull: NativeNice.CopyBackupMediaStream_next,
            convert: { value in
                return (
                    value.chunk.map { CopyBackupMediaOutcome($0) },
                    value.termination
                )
            },
            cancel: signal_copy_backup_media_stream_cancel,
        )
    }
}

/// A single item to copy from the attachment CDN to the backup CDN.
///
/// `encryptionKey` is the combined HMAC + AES key from ``BackupKey/deriveMediaEncryptionKey(_:)``
/// or ``BackupKey/deriveThumbnailTransitEncryptionKey(_:)``.
public struct CopyBackupMediaItem {
    public var sourceAttachmentCdn: Int32
    public var sourceKey: String
    public var objectLength: UInt64
    public var mediaId: Data
    public var encryptionKey: Data

    public init(
        sourceAttachmentCdn: Int32,
        sourceKey: String,
        objectLength: UInt64,
        mediaId: Data,
        encryptionKey: Data
    ) {
        self.sourceAttachmentCdn = sourceAttachmentCdn
        self.sourceKey = sourceKey
        self.objectLength = objectLength
        self.mediaId = mediaId
        self.encryptionKey = encryptionKey
    }

    fileprivate func toBridge() -> BridgeCopyBackupMediaItem {
        BridgeCopyBackupMediaItem(
            sourceAttachmentCdn: sourceAttachmentCdn,
            sourceKey: sourceKey,
            objectLength: Int64(objectLength),
            mediaId: mediaId,
            encryptionKey: encryptionKey
        )
    }
}

// swiftlint:disable explicit_init_for_public_struct - it's below the nested type
public struct CopyBackupMediaOutcome {
    public enum Result {
        case success(cdn: Int32)
        case sourceNotFound
        case wrongSourceLength
        case outOfSpace

        fileprivate init(_ result: BridgeCopyBackupMediaResult) {
            self =
                switch result {
                case .success(let cdn): .success(cdn: cdn)
                case .sourceNotFound: .sourceNotFound
                case .wrongSourceLength: .wrongSourceLength
                case .outOfSpace: .outOfSpace
                }
        }
    }

    public var mediaId: Data
    public var result: Result

    public init(mediaId: Data, result: Result) {
        self.mediaId = mediaId
        self.result = result
    }

    internal init(_ outcome: BridgeCopyBackupMediaOutcome) {
        self.mediaId = outcome.mediaId
        self.result = .init(outcome.result)
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthBackupsService> {
    public static var backups: Self { .init() }
}
extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthBackupsServiceImpl> {
    internal static var backupsImpl: Self { .init() }
}

internal class CopyBackupMediaStream: NativeHandleOwner<SignalMutPointerCopyBackupMediaStream> {
    override class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerCopyBackupMediaStream>
    ) -> SignalFfiErrorRef? {
        signal_copy_backup_media_stream_destroy(handle.pointer)
    }
}

extension SignalMutPointerCopyBackupMediaStream: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerCopyBackupMediaStream

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> SignalConstPointerCopyBackupMediaStream {
        .init(raw: self.raw)
    }

}
extension SignalConstPointerCopyBackupMediaStream: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
