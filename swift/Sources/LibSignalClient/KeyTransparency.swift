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
        public let aci: Aci
        public let identityKey: IdentityKey

        public init(aci: Aci, identityKey: IdentityKey) {
            self.aci = aci
            self.identityKey = identityKey
        }
    }

    /// E.164 descriptor for key transparency requests.
    public struct E164Info {
        public let e164: String
        public let unidentifiedAccessKey: Data

        public init(e164: String, unidentifiedAccessKey: Data) {
            self.e164 = e164
            self.unidentifiedAccessKey = unidentifiedAccessKey
        }
    }

    /// Mode of the key transparency operation.
    ///
    /// The behavior of ``KeyTransparencyClient/check`` differs depending on
    /// whether it is performed for the owner of the account or contact and in
    /// the former case whether the phone number discoverability is enabled.
    ///
    /// For example, if the newer version of account data is found in the key
    /// transparency log while monitoring "self", it will terminate with an
    /// error. However, the same check for a "contact" will result in a
    /// follow-up search operation.
    public enum CheckMode: Equatable {
        case `self`(isE164Discoverable: Bool)
        case contact

        fileprivate var isE164Discoverable: Bool? {
            switch self {
            case .self(let flag): flag
            case .contact: nil
            }
        }
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
    /// // Successful completion means the check succeeded with no further steps required.
    ///  try await chat.keyTransparencyClient.check(
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

        /// A unified key transparency operation that persistent a search, a
        /// monitor, or both.
        ///
        /// Caller should pass latest known values of all identifiers (ACI,
        /// E.164, username hash) associated with the account being monitored,
        /// along with the correct value of ``CheckMode``.
        ///
        /// If there is no data in the store for the account, the search
        /// operation will be performed. Following this initial search, the
        /// monitor operation will be used.
        ///
        /// If any of the fields in the monitor response contain a version that
        /// is higher than the one currently in the store, the behavior depends
        /// on the mode parameter value.
        /// - ``CheckMode/self`` - A ``SignalError/keyTransparencyError`` will
        ///   be returned, no search request will be issued.
        /// - ``CheckMode/contact`` - Another search request will be performed
        ///   automatically and, if it succeeds, the updated account data will
        ///   be stored.
        ///
        /// - Parameters:
        ///   - mode: Mode of the monitor operation. See ``CheckMode``.
        ///   - aciInfo: ACI identifying information.
        ///   - e164Info: E.164 identifying information. Optional.
        ///   - usernameHash: Hash of the username. Optional.
        ///   - store: Local key transparency storage. It will be queried for both
        ///     the account data  before sending the server request and, if the
        ///     request succeeds, will be updated with the check results.
        /// - Throws:
        ///   - ``SignalError/keyTransparencyError`` for errors related to key transparency logic, which
        ///     includes missing required fields in the serialized data. Retrying the search without
        ///     changing any of the arguments (including the state of the store) is unlikely to yield a
        ///     different result.
        ///   - ``SignalError/keyTransparencyVerificationFailed`` when it fails to
        ///     verify the data in key transparency server response, such as an incorrect proof or a
        ///     wrong signature. This is also the error thrown when new version
        ///     of account data is found in the key transparency log when
        ///     self-monitoring. See ``CheckMode``.
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
        public func check(
            for mode: CheckMode,
            account aciInfo: AciInfo,
            e164 e164Info: E164Info? = nil,
            usernameHash: Data? = nil,
            store: some Store
        ) async throws {
            let e164 = e164Info?.e164
            let uak = e164Info?.unidentifiedAccessKey

            let accountData = await store.getAccountData(for: aciInfo.aci)
            let knownDistinguished = await store.getLastDistinguishedTreeHead()

            let rawResponse = try await self.asyncContext.invokeAsyncFunction { promise, tokioContext in
                try! withAllBorrowed(
                    self.chatConnection,
                    aciInfo.aci,
                    aciInfo.identityKey.publicKey,
                    uak,
                    usernameHash,
                    accountData,
                    knownDistinguished
                ) { chatHandle, aciBytes, identityKeyHandle, uakBytes, hashBytes, accDataBytes, distinguishedBytes in
                    signal_key_transparency_check(
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
                        mode != .contact,
                        mode.isE164Discoverable ?? true
                    )
                }
            }
            let updatedAccountData = Data(consuming: rawResponse.first)
            let updatedDistinguished = Data(consuming: rawResponse.second)

            await store.setAccountData(updatedAccountData, for: aciInfo.aci)
            if !updatedDistinguished.isEmpty {
                await store.setLastDistinguishedTreeHead(to: updatedDistinguished)
            }
        }
    }
}
