//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Provides functionality for communicating with SVR3
///
/// `Svr3Client` instance can be obtained from ``Net/svr3`` property.
///
/// ## Example:
///
/// ~~~swift
/// // username and password provided by the Chat Server
/// let auth = try Auth(username: CHAT_USERNAME, password: CHAT_PASSWORD)
/// // Initialize an instance of Net
/// let net = Net(env: .staging)
/// // Store a value of SECRET_TO_BE_STORED in SVR3. Here 10 is the number of
/// // permitted restore attempts.
/// // Please note that the PASSWORD used here is **distinct** from the one used
/// // to create Auth.
/// let shareSet = try await net.svr3.backup(
///     SECRET_TO_BE_STORED,
///     password: PASSWORD,
///     maxTries: 10,
///     auth: auth
/// )
/// // Attempt to retrieve the secret from SVR3 provided the masked share set
/// // and a password.
/// let restoredSecret = try await net.svr3.restore(
///     password: PASSWORD,
///     shareSet: shareSet,
///     auth: auth
/// )
/// ~~~
public class Svr3Client {
    private let asyncContext: TokioAsyncContext
    private let connectionManager: ConnectionManager

    internal init(
        _ asyncContext: TokioAsyncContext,
        _ connectionManager: ConnectionManager
    ) {
        self.asyncContext = asyncContext
        self.connectionManager = connectionManager
    }

    /// Backup a secret to SVR3.
    ///
    /// - Parameters:
    ///   - secret: The secret to be stored. Must be 32 bytes long.
    ///   - password: User-provided password that will be used to derive the
    ///     encryption key for the secret.
    ///   - maxTries: Maximum allowed number of restore attempts (successful
    ///     or not). Each call to ``restore(password:shareSet:auth:)``
    ///     that reaches the server will decrement the counter. Must be
    ///     positive.
    ///   - auth: An instance of ``Auth`` containing the username and password
    ///     obtained from the Chat Server. The password is an OTP which is
    ///     generally good for about 15 minutes, therefore it can be reused for
    ///     the subsequent calls to either `backup` or `restore` that are not
    ///     too far apart in time.
    ///
    /// - Returns:
    ///   A byte array containing a serialized masked share set. It is supposed
    ///   to be an opaque blob for the clients and therefore no assumptions
    ///   should be made about its contents. This byte array should be stored by
    ///   the clients and used to restore the secret along with the password.
    ///   Please note that masked share set does not have to be treated as
    ///   secret.
    ///
    /// - Throws:
    ///   On error, throws a ``SignalError``. Expected error cases are
    ///   - `SignalError.networkError` for a network-level connectivity issue,
    ///     including connection timeout.
    ///   - `SignalError.networkProtocolError` for an SVR3 or attested
    ///     connection protocol issue.
    ///
    /// ## Notes:
    ///   - Error messages are log-safe and do not contain any sensitive data.
    ///   - Failures caused by the network issues (including a connection
    ///     timeout) can, in general, be retried, although there is already a
    ///     retry-with-backoff mechanism inside libsignal used to connect to the
    ///     SVR3 servers. Other exceptions are caused by the bad input or data
    ///     missing on the server. They are therefore non-actionable and are
    ///     guaranteed to be thrown again when retried.
    public func backup(
        _ secret: some ContiguousBytes,
        password: String,
        maxTries: UInt32,
        auth: Auth
    ) async throws -> [UInt8] {
        let output = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.connectionManager.withNativeHandle { connectionManager in
                secret.withUnsafeBorrowedBuffer { secretBuffer in
                    signal_svr3_backup(
                        promise,
                        asyncContext,
                        connectionManager,
                        secretBuffer,
                        password,
                        maxTries,
                        auth.username,
                        auth.password
                    )
                }
            }
        }
        defer {
            signal_free_buffer(output.base, output.length)
        }
        return Array(UnsafeBufferPointer(start: output.base, count: output.length))
    }

    /// Migrate a secret to a new SVR3 environment.
    ///
    /// Enclaves need to be updated from time to time and when they do, the
    /// stored secret needs to be migrated. From the API standpoint it is
    /// exactly like an ordinary backup operation, but internally it performs a
    /// backup to a new location combined with the remove from the old one. No
    /// data is read from the "old" location, that is, the restore operation is
    /// not performed.
    ///
    /// If the remove operation fails, this error is ignored.
    ///
    /// - Parameters:
    ///   - secret: The secret to be stored. Must be 32 bytes long.
    ///   - password: User-provided password that will be used to derive the
    ///     encryption key for the secret.
    ///   - maxTries: Maximum allowed number of restore attempts (successful
    ///     or not). Each call to ``restore(password:shareSet:auth:)``
    ///     that reaches the server will decrement the counter. Must be
    ///     positive.
    ///   - auth: An instance of ``Auth`` containing the username and password
    ///     obtained from the Chat Server. The password is an OTP which is
    ///     generally good for about 15 minutes, therefore it can be reused for
    ///     the subsequent calls to either `backup` or `restore` that are not
    ///     too far apart in time.
    ///
    /// - Returns:
    ///   A byte array containing a serialized masked share set. It is supposed
    ///   to be an opaque blob for the clients and therefore no assumptions
    ///   should be made about its contents. This byte array should be stored by
    ///   the clients and used to restore the secret along with the password.
    ///   Please note that masked share set does not have to be treated as
    ///   secret.
    ///
    /// - Throws:
    ///   On error, throws a ``SignalError``. Expected error cases are
    ///   - `SignalError.networkError` for a network-level connectivity issue,
    ///     including connection timeout.
    ///   - `SignalError.networkProtocolError` for an SVR3 or attested
    ///     connection protocol issue.
    ///
    /// ## Notes:
    ///   - Error messages are log-safe and do not contain any sensitive data.
    ///   - Failures caused by the network issues (including a connection
    ///     timeout) can, in general, be retried, although there is already a
    ///     retry-with-backoff mechanism inside libsignal used to connect to the
    ///     SVR3 servers. Other exceptions are caused by the bad input or data
    ///     missing on the server. They are therefore non-actionable and are
    ///     guaranteed to be thrown again when retried.
    public func migrate(
        _ secret: some ContiguousBytes,
        password: String,
        maxTries: UInt32,
        auth: Auth
    ) async throws -> [UInt8] {
        let output = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.connectionManager.withNativeHandle { connectionManager in
                secret.withUnsafeBorrowedBuffer { secretBuffer in
                    signal_svr3_migrate(
                        promise,
                        asyncContext,
                        connectionManager,
                        secretBuffer,
                        password,
                        maxTries,
                        auth.username,
                        auth.password
                    )
                }
            }
        }
        defer {
            signal_free_buffer(output.base, output.length)
        }
        return Array(UnsafeBufferPointer(start: output.base, count: output.length))
    }

    /// Restore a secret from SVR3.
    ///
    /// This function is safe to use during both the "normal" operation of SVR3
    /// and during enclave migration periods. In the latter case it will attempt
    /// reading from the "new" set of enclaves first, only when the backup is
    /// not found it will fall back to restoring from the "old" set of enclaves.
    /// However, if restore from "new" fails for any other reason, the fallback
    /// will not be attempted and the error will be returned immediately.
    ///
    /// - Parameters:
    ///   - password: User-provided password that will be used to derive the
    ///     encryption key for the secret.
    ///   - shareSet: A serialized masked share set returned by
    ///     ``backup(_:password:maxTries:auth:)``.
    ///   - auth: An instance of ``Auth`` containing the username and password
    ///     obtained from the Chat Server. The password is an OTP which is
    ///     generally good for about 15 minutes, therefore it can be reused for
    ///     the subsequent calls to either backup or restore that are not too
    ///     far apart in time.
    ///
    /// - Returns:
    ///   An instance of `RestoredSecret` containing the restored secret.
    ///
    /// - Throws:
    ///   On error, throws a ``SignalError``. Expected error cases are
    ///   - `SignalError.networkError` for a network-level connectivity issue,
    ///     including connection timeouts.
    ///   - `SignalError.networkProtocolError` for an SVR3 or attested
    ///     connection protocol issue.
    ///   - `SignalError.svrDataMissing` when either the maximum number of
    ///     restores has been exceeded or the value has never been backed up in
    ///     the first place.
    ///   - `SignalError.svrRestoreFailed` when the restore failed due to a bad
    ///     combination of password and share set.
    ///
    /// ## Notes:
    ///   - Error messages are log-safe and do not contain any sensitive data.
    ///   - Failures caused by the network issues (including a connection
    ///     timeout) can, in general, be retried, although there is already a
    ///     retry-with-backoff mechanism inside libsignal used to connect to the
    ///     SVR3 servers. Other exceptions are caused by the bad input or data
    ///     missing on the server. They are therefore non-actionable and are
    ///     guaranteed to be thrown again when retried.
    public func restore(
        password: String,
        shareSet: some ContiguousBytes,
        auth: Auth
    ) async throws -> RestoredSecret {
        let output = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.connectionManager.withNativeHandle { connectionManager in
                shareSet.withUnsafeBorrowedBuffer { shareSetBuffer in
                    signal_svr3_restore(
                        promise,
                        asyncContext,
                        connectionManager,
                        password,
                        shareSetBuffer,
                        auth.username,
                        auth.password
                    )
                }
            }
        }
        defer {
            signal_free_buffer(output.base, output.length)
        }
        let buffer = UnsafeBufferPointer(start: output.base, count: output.length)
        return RestoredSecret(fromBytes: buffer)
    }

    /// Remove a secret stored in SVR3.
    ///
    /// - Parameters:
    ///   - auth: An instance of ``Auth`` containing the username and password
    ///     obtained from the Chat Server. The password is an OTP which is
    ///     generally good for about 15 minutes, therefore it can be reused for
    ///     the subsequent calls to either backup or restore that are not too
    ///     far apart in time.
    ///
    /// - Throws:
    ///   On error, throws a ``SignalError``. Expected error cases are
    ///   - `SignalError.networkError` for a network-level connectivity issue,
    ///     including connection timeouts.
    ///   - `SignalError.networkProtocolError` for an SVR3 or attested
    ///     connection protocol issue.
    ///
    /// ## Notes:
    ///   - The method will succeed even if the data has never been backed up
    ///     in the first place.
    ///   - Error messages are log-safe and do not contain any sensitive data.
    ///   - Failures caused by the network issues (including a connection
    ///     timeout) can, in general, be retried, although there is already a
    ///     retry-with-backoff mechanism inside libsignal used to connect to the
    ///     SVR3 servers. Other exceptions are caused by the bad input or data
    ///     missing on the server. They are therefore non-actionable and are
    ///     guaranteed to be thrown again when retried.
    public func remove(auth: Auth) async throws {
        _ = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.connectionManager.withNativeHandle { connectionManager in
                signal_svr3_remove(promise, asyncContext, connectionManager, auth.username, auth.password)
            }
        }
    }

    /// Rotate the secret stored in SVR3.
    ///
    /// This operation will not invalidate the share set stored on the client.
    /// It needs to be called periodically to further protect the secret from
    /// "harvest now decrypt later" attacks.
    ///
    /// Secret rotation is a multi-step process and may require multiple round
    /// trips to the server, however it is guaranteed to not hang indefinitely
    /// and will bail out after a predefined number of attempts.
    ///
    /// - Parameters:
    ///   - shareSet: A serialized masked share set returned by
    ///     ``backup(_:password:maxTries:auth:)``.
    ///   - auth: An instance of ``Auth`` containing the username and password
    ///     obtained from the Chat Server. The password is an OTP which is
    ///     generally good for about 15 minutes, therefore it can be reused for
    ///     the subsequent calls to either backup or restore that are not too
    ///     far apart in time.
    ///
    /// - Throws:
    ///   On error, throws a ``SignalError``. Expected error cases are
    ///   - `SignalError.networkError` for a network-level connectivity issue,
    ///     including connection timeout.
    ///   - `SignalError.networkProtocolError` for an SVR3 or attested
    ///     connection protocol issue.
    ///
    /// ## Notes:
    ///   - Error messages are log-safe and do not contain any sensitive data.
    ///   - Failures caused by the network issues (including a connection
    ///     timeout) can, in general, be retried, although there is already a
    ///     retry-with-backoff mechanism inside libsignal used to connect to the
    ///     SVR3 servers. Other exceptions are caused by the bad input or data
    ///     missing on the server. They are therefore non-actionable and are
    ///     guaranteed to be thrown again when retried.
    ///   - Failure to complete the secret rotation in a predefined number of
    ///     attempts can (but does not have to) be retried. Failure to rotate
    ///     does not invalidate any data and the next scheduled rotation will be
    ///     able to complete the process.
    public func rotate(shareSet: some ContiguousBytes, auth: Auth) async throws {
        _ = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.connectionManager.withNativeHandle { connectionManager in
                shareSet.withUnsafeBorrowedBuffer { shareSetBuffer in
                    signal_svr3_rotate(
                        promise,
                        asyncContext,
                        connectionManager,
                        shareSetBuffer,
                        auth.username,
                        auth.password
                    )
                }
            }
        }
    }
}

public struct RestoredSecret: Sendable {
    public let value: [UInt8]
    public let triesRemaining: UInt32

    init(fromBytes bytes: UnsafeBufferPointer<UInt8>) {
        let (prefix, suffix) = bytes.split(at: MemoryLayout<UInt32>.size)
        self.triesRemaining = UInt32(bigEndian: prefix)
        self.value = Array(suffix)
    }
}

extension UInt32 {
    internal init<Bytes: Collection>(bigEndian bytes: Bytes) where Bytes.Element == UInt8 {
        precondition(bytes.count == MemoryLayout<Self>.size)
        var value = Self()
        for byte in bytes {
            value = (value << 8) + UInt32(byte)
        }
        self = value
    }
}
