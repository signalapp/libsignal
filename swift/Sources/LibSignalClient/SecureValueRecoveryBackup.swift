//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

// MARK: - SvrB Service

/// Service for Secure Value Recovery for Backups (SVR-B) operations.
///
/// This service provides forward secrecy for Signal backups using SVR-B. Forward secrecy ensures
/// that even if the user's Account Entropy Pool or Backup Key is compromised, the attacker can
/// decrypt only a very small number of past backups. This is achieved by storing a token
/// in a secure enclave inside the SVR-B server, which provably attests that it
/// only stores a single token at a time for each user.
///
/// ## Overview
///
/// To achieve these properties, a secret token is required to derive the actual encryption
/// keys for the backup. At backup time, this token must be stored in the SVR-B server, overwriting the
/// previous token. At restore time, the token must be retrieved from the SVR-B server, and used to
/// derive the encryption keys for the backup.
///
/// ## Storage Flow
///
/// 1. Create a ``Net`` instance and get the `SvrB` service via ``Net/svrB(auth:)``
/// 2. If this is a fresh install, call ``createNewBackupChain(backupKey:)`` and store the result locally.
///    Otherwise, retrieve the secret data from the last **successful** backup operation (store or restore).
/// 3. Call ``store(backupKey:previousSecretData:)``, passing the data from step (2).
/// 4. Use the returned forward secrecy token to derive encryption keys
/// 5. Encrypt and upload the backup data to the user's remote, off-device storage location, including the
///    returned ``StoreBackupResponse/metadata``. The upload **must succeed**
///    before proceeding or the previous backup might become unretrievable.
/// 5. Store the returned ``StoreBackupResponse/nextBackupSecretData`` locally, overwriting any previously-saved value.
///
/// ## Secret handling
///
/// When calling ``store(backupKey:previousSecretData:)``, the `previousSecretData` parameter must
/// be from the last call to  `store` or `restore` that succeeded. This "chaining" is used to
/// construct each backup file so that it can be decrypted with either the *previous* token stored
/// in SVR-B, or the *next* one, which is important in case the overall backup upload is ever
/// interrupted.
///
/// The returned secret from a successful store or restore should be persisted until it is
/// overwritten by the value from a subsequent successful call. The caller should use
/// ``createNewBackupChain(backupKey:)`` only for the very first backup with a particular backup
/// key.
///
/// ## Restore Flow
///
/// 1. Create a ``Net`` instance and get the ``SvrB`` service via ``Net/svrB(auth:)``
/// 2. Fetch the backup metadata from storage
/// 3. Call ``restore(backupKey:metadata:)`` to get the forward secrecy token
/// 4. Use the token to derive decryption keys
/// 5. Decrypt and restore the backup data
/// 6. Store the returned ``RestoreBackupResponse/nextBackupSecretData`` locally.
///
/// ## Usage
/// ```swift
/// let net = Net(env: .production, userAgent: "MyApp")
/// let auth = Auth(username: "username", password: "password")
/// let svrB = net.svrB(auth: auth)
///
/// // Prepare a backup
/// let response = try svrB.storeBackup(backupKey: myKey, previousSecretData: previousSecretData)
/// // ... store backup with response.forwardSecrecyToken ...
/// // Securely store response.nextBackupSecretData for the next backup
/// ```
///
/// - SeeAlso: ``BackupKey``, ``MessageBackupKey``, ``BackupForwardSecrecyToken``
public class SvrB {
    private let net: Net
    private let auth: Auth

    internal init(net: Net, auth: Auth) {
        self.net = net
        self.auth = auth
    }

    /// Generates backup "secret data" for a fresh install.
    ///
    /// Should not be used if any previous backups exist for this `backupKey`, whether uploaded or restored by the local device.
    /// See ``SvrB`` for more information.
    public func createNewBackupChain(backupKey: BackupKey) -> Data {
        backupKey.withUnsafePointer { backupKey in
            failOnError {
                try invokeFnReturningData {
                    signal_secure_value_recovery_for_backups_create_new_backup_chain(
                        $0,
                        net.environment.rawValue,
                        backupKey
                    )
                }
            }
        }
    }

    /// Prepares a backup for storage with forward secrecy guarantees.
    ///
    /// This makes a network call to the SVR-B server to store the forward secrecy token and returns
    /// a ``StoreBackupResponse``. See its fields' documentation and ``SvrB`` for how to continue
    /// persisting the backup on success.
    ///
    /// - Parameters:
    ///   - backupKey: The backup key derived from the Account Entropy Pool (AEP).
    ///   - previousSecretData: Secret data from the most recent previous backup operation.
    ///     **Critical**: This MUST be the secret data from the most recent of the following:
    ///     - the last **successful** ``store(backupKey:previousSecretData:)`` call whose returned
    ///       `metadata` was successfully uploaded, and whose `nextBackupSecretData` was persisted.
    ///     - the last successful ``restore(backupKey:metadata:)``
    ///     - the already-persisted result from ``createNewBackupChain(backupKey:)``, only if
    ///       neither of the other two are available
    /// - Returns: A ``StoreBackupResponse`` containing the forward secrecy token, metadata, and
    ///   secret data.
    /// - Throws:
    ///   - ``SignalError/invalidArgument(_:)`` if `previousSecretData` is malformed. There's no
    ///     choice here but to **start a new chain**.
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server is rate limiting
    ///     this client. This is **retryable** after waiting the designated delay.
    ///   - ``SignalError/connectionFailed(_:)``, ``SignalError/ioError(_:)``, or
    ///     ``SignalError/webSocketError(_:)`` for networking failures before and during
    ///     communication with the server. These can be **automatically retried** (backoff
    ///     recommended).
    ///   - Other ``SignalError``s for networking and attestation issues. These can be manually
    ///     retried, but some may indicate a possible bug in libsignal or in the enclave.
    public func store(
        backupKey: BackupKey,
        previousSecretData: Data
    ) async throws -> StoreBackupResponse {
        let rawResult = try await self.net.asyncContext.invokeAsyncFunction { promise, runtime in
            net.connectionManager.withNativeHandle { connectionManager in
                backupKey.withUnsafePointer { backupKey in
                    previousSecretData.withBorrowed { previousSecretData in
                        signal_secure_value_recovery_for_backups_store_backup(
                            promise,
                            runtime.const(),
                            backupKey,
                            previousSecretData,
                            connectionManager.const(),
                            self.auth.username,
                            self.auth.password
                        )
                    }
                }
            }
        }

        return StoreBackupResponse(owned: NonNull(rawResult)!)
    }

    /// Fetches the forward secrecy token needed to decrypt a backup.
    ///
    /// This function makes a network call to the SVR-B server to retrieve the forward secrecy token
    /// associated with a specific backup. The token is required to derive the message backup keys
    /// for decryption.
    ///
    /// The typical restore flow:
    /// 1. Fetch the backup metadata (stored in a header in the backup file)
    /// 2. Call this function to retrieve the forward secrecy token from SVR-B
    /// 3. Use the token to derive message backup keys
    /// 4. Decrypt and restore the backup data
    /// 5. Store the returned ``RestoreBackupResponse/nextBackupSecretData`` locally.
    ///
    /// - Parameters:
    ///   - backupKey: The backup key derived from the Account Entropy Pool (AEP).
    ///   - metadata: The metadata that was stored in a header in the backup file during backup
    ///     creation.
    /// - Returns: The forward secrecy token needed to derive keys for decrypting the backup.
    /// - Throws:
    ///   - ``SignalError/invalidArgument(_:)`` if the backup metadata is malformed. In this case
    ///     the user's data is **not recoverable**.
    ///   - ``SignalError/svrRestoreFailed(triesRemaining:message:)`` if restoration fails. This
    ///     should never happen but if it does the user's data is **not recoverable**.
    ///   - ``SignalError/svrDataMissing(_:)`` if the backup data is not found on the server,
    ///     indicating an **incorrect backup key** (which may in turn imply the user's data is not
    ///     recoverable).
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server is rate limiting
    ///     this client. This is **retryable** after waiting the designated delay.
    ///   - ``SignalError/connectionFailed(_:)``, ``SignalError/ioError(_:)``, or
    ///     ``SignalError/webSocketError(_:)`` for networking failures before and during
    ///     communication with the server. These can be **automatically retried** (backoff
    ///     recommended).
    ///   - Other ``SignalError``s for networking and attestation issues. These can be manually
    ///     retried, but some may indicate a possible bug in libsignal or in the enclave.
    public func restore(
        backupKey: BackupKey,
        metadata: Data
    ) async throws -> RestoreBackupResponse {
        let rawResult = try await self.net.asyncContext.invokeAsyncFunction {
            promise,
            runtime in
            net.connectionManager.withNativeHandle { connectionManager in
                backupKey.withUnsafePointer { keyBuffer in
                    metadata.withUnsafeBorrowedBuffer { metadataBuffer in
                        signal_secure_value_recovery_for_backups_restore_backup_from_server(
                            promise,
                            runtime.const(),
                            keyBuffer,
                            metadataBuffer,
                            connectionManager.const(),
                            self.auth.username,
                            self.auth.password
                        )
                    }
                }
            }
        }

        return RestoreBackupResponse(owned: NonNull(rawResult)!)
    }

    /// Attempts to remove the info stored with SVR-B for this particular username/password pair.
    ///
    /// This is a best-effort operation; a successful return means the data has been removed from
    /// (or never was present in) the current SVR-B enclaves, but may still be present in previous
    /// ones that have yet to be decommissioned. Conversely, a thrown error may still have removed
    /// information from previous enclaves.
    ///
    /// This should not typically be needed; rather than explicitly removing an entry, the client
    /// should generally overwrite with a new ``store(backupKey:previousSecretData:)`` instead.
    ///
    /// - Throws:
    ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server is rate limiting
    ///     this client. This is **retryable** after waiting the designated delay.
    ///   - ``SignalError/connectionFailed(_:)``, ``SignalError/ioError(_:)``, or
    ///     ``SignalError/webSocketError(_:)`` for networking failures before and during
    ///     communication with the server. These can be **automatically retried** (backoff
    ///     recommended).
    ///   - Other ``SignalError``s for networking and attestation issues. These can be manually
    ///     retried, but some may indicate a possible bug in libsignal or in the enclave.
    public func remove() async throws {
        let _: Bool = try await self.net.asyncContext.invokeAsyncFunction {
            promise,
            runtime in
            net.connectionManager.withNativeHandle { connectionManager in
                signal_secure_value_recovery_for_backups_remove_backup(
                    promise,
                    runtime.const(),
                    connectionManager.const(),
                    self.auth.username,
                    self.auth.password
                )
            }
        }
    }
}

// MARK: - Type Definitions

extension SvrB {
    /// The result of preparing a backup to be stored with forward secrecy guarantees.
    ///
    /// This context contains all the necessary components to encrypt and store a backup using a
    /// key derived from both the user's Account Entropy Pool and the SVR-B-protected
    /// Forward Secrecy Token.
    ///
    /// - SeeAlso: ``BackupForwardSecrecyToken``
    public class StoreBackupResponse: NativeHandleOwner<SignalMutPointerBackupStoreResponse> {
        override internal class func destroyNativeHandle(
            _ handle: NonNull<SignalMutPointerBackupStoreResponse>
        ) -> SignalFfiErrorRef? {
            signal_backup_store_response_destroy(handle.pointer)
        }

        /// The forward secrecy token used to derive ``MessageBackupKey`` instances.
        ///
        /// This token provides forward secrecy guarantees by ensuring that compromise of the backup key
        /// alone is insufficient to decrypt backups. Each backup is protected by a value stored on
        /// the SVR-B server that must be retrieved during restoration.
        public var forwardSecrecyToken: BackupForwardSecrecyToken {
            withNativeHandle { nativeHandle in
                failOnError {
                    let data = try invokeFnReturningFixedLengthArray {
                        signal_backup_store_response_get_forward_secrecy_token($0, nativeHandle.const())
                    }
                    return try BackupForwardSecrecyToken(contents: data)
                }
            }
        }

        /// Opaque metadata that must be stored alongside the backup file.
        ///
        /// This metadata contains the encrypted forward secrecy token and other information required
        /// to restore the backup. It must be retrievable when restoring the backup, as it's required
        /// to fetch the forward secrecy token from SVR-B. This is currently stored in the header of
        /// the backup file.
        public var metadata: Data {
            withNativeHandle { nativeHandle in
                failOnError {
                    try invokeFnReturningData {
                        signal_backup_store_response_get_opaque_metadata($0, nativeHandle.const())
                    }
                }
            }
        }

        /// Opaque value that must be persisted and provided to the next call to ``SvrB/store(backupKey:previousSecretData:)``.
        ///
        /// See the ``SvrB`` documentation for lifecycle and persistence handling
        /// for this value.
        ///
        public var nextBackupSecretData: Data {
            withNativeHandle { nativeHandle in
                failOnError {
                    try invokeFnReturningData {
                        signal_backup_store_response_get_next_backup_secret_data($0, nativeHandle.const())
                    }
                }
            }
        }
    }
    /// The result of preparing a backup to be stored with forward secrecy guarantees.
    ///
    /// This context contains all the necessary components to encrypt and store a backup using a
    /// key derived from both the user's Account Entropy Pool and the SVR-B-protected
    /// Forward Secrecy Token.
    ///
    /// - SeeAlso: ``BackupForwardSecrecyToken``
    public class RestoreBackupResponse: NativeHandleOwner<SignalMutPointerBackupRestoreResponse> {
        override internal class func destroyNativeHandle(
            _ handle: NonNull<SignalMutPointerBackupRestoreResponse>
        ) -> SignalFfiErrorRef? {
            signal_backup_restore_response_destroy(handle.pointer)
        }

        /// The forward secrecy token used to derive ``MessageBackupKey`` instances.
        ///
        /// This token provides forward secrecy guarantees by ensuring that compromise of the backup key
        /// alone is insufficient to decrypt backups. Each backup is protected by a value stored on
        /// the SVR-B server that must be retrieved during restoration.
        public var forwardSecrecyToken: BackupForwardSecrecyToken {
            withNativeHandle { nativeHandle in
                failOnError {
                    let data = try invokeFnReturningFixedLengthArray {
                        signal_backup_restore_response_get_forward_secrecy_token($0, nativeHandle.const())
                    }
                    return try BackupForwardSecrecyToken(contents: data)
                }
            }
        }

        /// Opaque value that must be persisted and provided to the next call to ``SvrB/store(backupKey:previousSecretData:)``.
        ///
        /// See the ``SvrB`` documentation for lifecycle and persistence handling
        /// for this value.
        ///
        public var nextBackupSecretData: Data {
            withNativeHandle { nativeHandle in
                failOnError {
                    try invokeFnReturningData {
                        signal_backup_restore_response_get_next_backup_secret_data($0, nativeHandle.const())
                    }
                }
            }
        }
    }
}

// MARK: - SignalMutPointer Conformances

extension SignalMutPointerBackupStoreResponse: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerBackupStoreResponse

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerBackupStoreResponse: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerBackupRestoreResponse: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerBackupRestoreResponse

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerBackupRestoreResponse: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
