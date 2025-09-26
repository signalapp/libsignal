//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum KeyTransparency {
    /// Protocol for a local persistent key transparency data store.
    ///
    /// Contents of the store are opaque to the client and are only supposed to be
    /// used by the ``Client``.
    ///
    public protocol Store {
        func getLastDistinguishedTreeHead() async -> Data?
        func setLastDistinguishedTreeHead(to: Data) async
        func getAccountData(for aci: Aci) async -> Data?
        func setAccountData(_ data: Data, for aci: Aci) async
    }

    /// ACI descriptor for key transparency requests.
    public struct AciInfo {
        let aci: Aci
        let identityKey: IdentityKey
    }

    /// E.164 descriptor for key transparency requests.
    public struct E164Info {
        let e164: String
        let unidentifiedAccessKey: Data
    }

    /// Mode of the monitor operation.
    ///
    /// If the newer version of account data is found in the key transparency
    /// log, self-monitor will terminate with an error, but monitor for other
    /// account will fall back to a full search and update the locally stored
    /// data.
    public enum MonitorMode {
        case `self`
        case other
    }

    /// Typed API to access the key transparency subsystem using an existing
    /// unauthenticated chat connection.
    ///
    /// Unlike ``UnauthenticatedChatConnection``, the client does
    /// not export "raw" send/receive APIs, and instead uses them internally to
    /// implement high-level key transparency operations.
    ///
    /// Instances should be obtained by using the
    /// ``UnauthenticatedChatConnection/keyTransparencyClient`` property.
    ///
    /// Example usage:
    ///
    /// ```swift
    /// let network = Net(
    ///   env: .staging,
    ///   userAgent: "key-transparency-example"
    /// )
    ///
    /// let chat = try await network.connectUnauthenticatedChat()
    /// chat.start(listener: MyChatListener())
    ///
    /// // Successful completion means the search succeeded with no further steps required.
    ///  try await chat.keyTransparencyClient.search(
    ///      account: myAciInfo,
    ///      e164: myE164Info,
    ///      store: store
    ///  )
    /// ```
    public class Client {
        private let chatConnection: UnauthenticatedChatConnection
        private let asyncContext: TokioAsyncContext
        private let environment: Net.Environment

        internal init(
            chatConnection: UnauthenticatedChatConnection,
            asyncContext: TokioAsyncContext,
            environment: Net.Environment
        ) {
            self.chatConnection = chatConnection
            self.asyncContext = asyncContext
            self.environment = environment
        }

        /// Search for account information in the key transparency tree.
        ///
        /// - Parameters:
        ///   - aciInfo: ACI identifying information.
        ///   - e164Info: E.164 identifying information. Optional.
        ///   - usernameHash: Hash of the username. Optional.
        ///   - store: Local key transparency storage. It will be queried for both
        ///     the account data and the latest distinguished tree head before sending the
        ///     server request and, if the request succeeds, will be updated with the
        ///     search operation results.
        /// - Throws:
        ///   - ``SignalError/keyTransparencyError`` for errors related to key transparency logic, which
        ///     includes missing required fields in the serialized data. Retrying the search without
        ///     changing any of the arguments (including the state of the store) is unlikely to yield a
        ///     different result.
        ///   - ``SignalError/keyTransparencyVerificationFailed`` when it fails to
        ///     verify the data in key transparency server response, such as an incorrect proof or a
        ///     wrong signature.
        ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server is rate limiting
        ///     this client. This is **retryable** after waiting the designated delay.
        ///   - ``SignalError/connectionFailed(_:)``, ``SignalError/ioError(_:)``, or
        ///     ``SignalError/webSocketError(_:)`` for networking failures before and during
        ///     communication with the server. These can be **automatically retried** (backoff
        ///     recommended).
        ///   - Other ``SignalError``s for networking issues. These can be manually
        ///     retried, but some may indicate a possible bug in libsignal.
        ///
        /// Completes successfully if the search succeeds and the local state has been
        /// updated to reflect the latest changes. If the operation fails, the UI should
        /// be updated to notify the user of the failure.
        public func search(
            account aciInfo: AciInfo,
            e164 e164Info: E164Info? = nil,
            usernameHash: Data? = nil,
            store: some Store
        ) async throws {
            let e164 = e164Info?.e164
            let uak = e164Info?.unidentifiedAccessKey

            let accountData = await store.getAccountData(for: aciInfo.aci)
            let distinguished = try await self.updateDistinguished(store)

            let bytes = try await self.asyncContext.invokeAsyncFunction { promise, tokioContext in
                try! withAllBorrowed(
                    self.chatConnection,
                    aciInfo.aci,
                    aciInfo.identityKey.publicKey,
                    uak,
                    usernameHash,
                    accountData,
                    distinguished
                ) { chatHandle, aciBytes, identityKeyHandle, uakBytes, hashBytes, accDataBytes, distinguishedBytes in
                    signal_key_transparency_search(
                        promise,
                        tokioContext.const(),
                        self.environment.rawValue,
                        chatHandle.const(),
                        aciBytes,
                        identityKeyHandle.const(),
                        e164,
                        uakBytes,
                        hashBytes,
                        accDataBytes,
                        distinguishedBytes
                    )
                }
            }
            await store.setAccountData(Data(consuming: bytes), for: aciInfo.aci)
        }

        /// Perform a monitor operation for an account previously searched for.
        ///
        /// - Parameters:
        ///   - mode: Mode of the monitor operation. See ``MonitorMode``.
        ///   - aciInfo: ACI identifying information.
        ///   - e164Info: E.164 identifying information. Optional.
        ///   - usernameHash: Hash of the username. Optional.
        ///   - store: Local key transparency storage. It will be queried for both
        ///     the account data and the latest distinguished tree head before sending the
        ///     server request and, if the request succeeds, will be updated with the
        ///     search operation results.
        /// - Throws:
        ///   - ``SignalErrorrkeyTransparencyError`` for errors related to key transparency logic, which
        ///     includes missing required fields in the serialized data. Retrying the search without
        ///     changing any of the arguments (including the state of the store) is unlikely to yield a
        ///     different result.
        ///   - ``SignalError/keyTransparencyVerificationFailed`` when it fails to
        ///     verify the data in key transparency server response, such as an incorrect proof or a
        ///     wrong signature. This is also the error thrown when new version
        ///     of account data is found in the key transparency log when
        ///     self-monitoring. See ``MonitorMode``.
        ///   - ``SignalError/rateLimitedError(retryAfter:message:)`` if the server is rate limiting
        ///     this client. This is **retryable** after waiting the designated delay.
        ///   - ``SignalError/connectionFailed(_:)``, ``SignalError/ioError(_:)``, or
        ///     ``SignalError/webSocketError(_:)`` for networking failures before and during
        ///     communication with the server. These can be **automatically retried** (backoff
        ///     recommended).
        ///   - Other ``SignalError``s for networking issues. These can be manually
        ///     retried, but some may indicate a possible bug in libsignal.
        ///
        ///
        /// Completes successfully if the search succeeds and the local state has been
        /// updated to reflect the latest changes. If the operation fails, the UI should
        /// be updated to notify the user of the failure.
        public func monitor(
            for mode: MonitorMode,
            account aciInfo: AciInfo,
            e164 e164Info: E164Info? = nil,
            usernameHash: Data? = nil,
            store: some Store
        ) async throws {
            let e164 = e164Info?.e164
            let uak = e164Info?.unidentifiedAccessKey

            let accountData = await store.getAccountData(for: aciInfo.aci)
            let distinguished = try await self.updateDistinguished(store)

            let bytes = try await self.asyncContext.invokeAsyncFunction { promise, tokioContext in
                try! withAllBorrowed(
                    self.chatConnection,
                    aciInfo.aci,
                    aciInfo.identityKey.publicKey,
                    uak,
                    usernameHash,
                    accountData,
                    distinguished
                ) { chatHandle, aciBytes, identityKeyHandle, uakBytes, hashBytes, accDataBytes, distinguishedBytes in
                    signal_key_transparency_monitor(
                        promise,
                        tokioContext.const(),
                        self.environment.rawValue,
                        chatHandle.const(),
                        aciBytes,
                        identityKeyHandle.const(),
                        e164,
                        uakBytes,
                        hashBytes,
                        accDataBytes,
                        distinguishedBytes,
                        mode == .self
                    )
                }
            }
            await store.setAccountData(Data(consuming: bytes), for: aciInfo.aci)
        }

        private func updateDistinguished(_ store: some Store) async throws -> Data {
            let knownDistinguished = await store.getLastDistinguishedTreeHead()
            let latestDistinguished = try await getDistinguished(knownDistinguished)
            await store.setLastDistinguishedTreeHead(to: latestDistinguished)
            return latestDistinguished
        }

        internal func getDistinguished(
            _ distinguished: Data? = nil
        ) async throws -> Data {
            let bytes = try await self.asyncContext.invokeAsyncFunction { promise, tokioContext in
                try! withAllBorrowed(self.chatConnection, distinguished) { chatHandle, distinguishedBytes in
                    signal_key_transparency_distinguished(
                        promise,
                        tokioContext.const(),
                        self.environment.rawValue,
                        chatHandle.const(),
                        distinguishedBytes
                    )
                }
            }
            return Data(consuming: bytes)
        }
    }
}
