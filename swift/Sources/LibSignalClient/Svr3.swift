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
    ///   - Error messages are expected to be log-safe and not contain any
    ///     sensitive data.
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
        let output = try await invokeAsyncFunction(returning: SignalOwnedBuffer.self) { promise, context in
            self.asyncContext.withNativeHandle { asyncContext in
                self.connectionManager.withNativeHandle { connectionManager in
                    secret.withUnsafeBorrowedBuffer { secretBuffer in
                        signal_svr3_backup(
                            promise,
                            context,
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
        }
        defer {
            signal_free_buffer(output.base, output.length)
        }
        return Array(UnsafeBufferPointer(start: output.base, count: output.length))
    }

    /// Restore a secret from SVR3.
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
    ///   A byte array containing the restored secret.
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
    ///   - Error messages are expected to be log-safe and not contain any
    ///     sensitive data.
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
    ) async throws -> [UInt8] {
        let output = try await invokeAsyncFunction(returning: SignalOwnedBuffer.self) { promise, context in
            self.asyncContext.withNativeHandle { asyncContext in
                self.connectionManager.withNativeHandle { connectionManager in
                    shareSet.withUnsafeBorrowedBuffer { shareSetBuffer in
                        signal_svr3_restore(
                            promise,
                            context,
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
        }
        defer {
            signal_free_buffer(output.base, output.length)
        }
        return Array(UnsafeBufferPointer(start: output.base, count: output.length))
    }
}
