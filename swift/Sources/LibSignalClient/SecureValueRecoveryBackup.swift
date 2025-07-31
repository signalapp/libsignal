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
/// 2. Call ``store(backupKey:previousSecretData:)``
///    - Pass the secret data from the last **successful** ``store(backupKey:previousSecretData:)`` or
///      ``restore(backupKey:metadata:)`` call
///    - If no previous backup exists or the secret data is unavailable, pass `nil`
/// 3. Use the returned forward secrecy token to derive encryption keys
/// 4. Encrypt and upload the backup data to the user's remote, off-device storage location, including the
///    returned ``StoreBackupResponse/metadata``. The upload **must succeed**
///    before proceeding or the previous backup might become unretrievable.
/// 5. Store the returned ``StoreBackupResponse/nextBackupSecretData`` locally, overwriting any previously-saved value.
///
/// ## Secret handling
///
/// When calling ``store(backupKey:previousSecretData:)``, the `previousSecretData` parameter
/// must be from the last call to `store` or `restore` that
/// succeeded. The returned secret from a successful `store` or `restore` call should
/// be persisted until it is overwritten by the value from a subsequent successful call.
/// The caller should pass `nil` as `previousSecretData` only for the very first backup from a device.
///
/// ## Restore Flow
///
/// 1. Create a ``Net`` instance and get the ``SvrB`` service via ``Net/svrB(auth:)``
/// 2. Fetch the backup metadata from storage
/// 3. Call ``fetchForwardSecrecyTokenFromServer(backupKey:metadata:)`` to get the forward secrecy token
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

    /// Prepares a backup for storage with forward secrecy guarantees.
    ///
    /// This makes a network call to the SVR-B server to store the forward secrecy token
    /// and returns a ``StoreBackupResponse``. See its fields' documentation and ``SvrB``
    /// for how to continue persisting the backup on success.
    ///
    /// - Parameters:
    ///   - backupKey: The backup key derived from the Account Entropy Pool (AEP).
    ///   - previousSecretData: Optional secret data from the most recent previous backup.
    ///     **Critical**: This MUST be the secret data from the last ``store(backupKey:previousSecretKey:)``
    ///     or ``restore(backupKey:metadata:)`` call whose returned `metadata` was successfully uploaded,
    ///     and whose `nextBackupSecretData` was persisted.
    ///     If `nil`, starts a new chain and renders any prior backups unretrievable; this should
    ///     only be used for the very first backup from a device.
    /// - Returns: A ``StoreBackupResponse`` containing the forward secrecy token, metadata, and secret data.
    /// - Throws: ``SignalError`` if the previous secret data is malformed or processing or upload fail.
    public func store(
        backupKey: BackupKey,
        previousSecretData: Data?
    ) async throws -> StoreBackupResponse {
        let rawResult = try await self.net.asyncContext.invokeAsyncFunction { promise, runtime in
            net.connectionManager.withNativeHandle { connectionManager in
                backupKey.withUnsafePointer { backupKey in
                    (previousSecretData ?? Data()).withBorrowed { previousSecretData in
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
    /// 5. Store the returned ``SvrB/RestoreBackupResponse/nextBackupSecretData`` locally.
    ///
    /// - Parameters:
    ///   - backupKey: The backup key derived from the Account Entropy Pool (AEP).
    ///   - metadata: The metadata that was stored in a header in the backup file during backup creation.
    /// - Returns: The forward secrecy token needed to derive keys for decrypting the backup.
    /// - Throws: ``SignalError`` if the metadata is invalid, the network operation fails, or the
    ///   backup cannot be found.
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
