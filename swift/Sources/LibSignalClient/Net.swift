//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Entry point for interacting with Signal remote services.
public class Net {
    /// The Signal environment to use when connecting to remote services.
    ///
    /// The services running in each environment are distinct, and operations
    /// for one do not affect the other.
    public enum Environment: UInt8 {
        // This needs to be kept in sync with the Rust version of the enum.

        /// Signal's staging environment.
        case staging = 0

        /// Signal's production environment.
        case production = 1
    }

    /// Creates a new `Net` instance that enables interacting with services in the given Signal environment.
    public init(env: Environment) {
        self.asyncContext = TokioAsyncContext()
        self.connectionManager = ConnectionManager(env: env)
    }

    /// Like ``cdsiLookup(auth:request:timeout:)`` but with the parameters to ``CdsiLookupRequest`` broken out.
    public func cdsiLookup(
        auth: Auth,
        prevE164s: [String],
        e164s: [String],
        acisAndAccessKeys: [AciAndAccessKey],
        returnAcisWithoutUaks: Bool,
        token: Data?,
        timeout: TimeInterval
    ) async throws -> CdsiLookup {
        let request = try CdsiLookupRequest(e164s: e164s, prevE164s: prevE164s, acisAndAccessKeys: acisAndAccessKeys, token: token, returnAcisWithoutUaks: returnAcisWithoutUaks)
        return try await self.cdsiLookup(auth: auth, request: request, timeout: timeout)
    }

    /// Starts a new CDSI lookup request.
    ///
    /// Initiates a new CDSI request. Once the attested connection has been
    /// established and the request received, this method returns a
    /// ``CdsiLookup`` object that can be used to continue the in-progress
    /// request.
    ///
    /// - Parameters:
    ///   - auth: The information to use when authenticating with the CDSI server.
    ///   - request: The CDSI request to be sent to the server.
    ///   - timeout: The amount of time to wait for the initial connection before giving up.
    ///
    /// - Returns:
    ///   An object representing the in-progress request. If this method
    ///   succeeds, that means the server accepted the request and produced a
    ///   token in response. See ``CdsiLookup`` for more.
    ///
    /// - Throws: On error, throws a ``SignalError``. Expected error cases are
    ///   `SignalError.networkError` for a network-level connectivity issue,
    ///   `SignalError.networkProtocolError` for a CDSI or attested connection protocol issue,
    ///   `SignalError.rateLimitedError` with the amount of time to wait before trying again.
    ///
    /// ## Example:
    ///
    /// ```swift
    /// // Assemble request info.
    /// let auth = Auth(/* auth args from chat server */)
    /// let request = try CdsiLookupRequest(/* args */)
    ///
    /// // Start the request.
    /// let net = Net(env: Net.Environment.production)
    /// let lookup = try await net.cdsiLookup(auth: auth, request: request, timeout: TimeInterval(10))
    ///
    /// // Save the token for future lookups.
    /// let savedToken = lookup.token
    /// let result = try await lookup.complete()
    ///
    /// // Do something with the response.
    /// for entry in result.entries {
    ///   doSomething(entry.aci, entry.pni, entry.e164)
    /// }
    /// ```
    public func cdsiLookup(
        auth: Auth,
        request: CdsiLookupRequest,
        timeout: TimeInterval
    ) async throws -> CdsiLookup {
        let timeoutMs = durationToMillis(timeout)
        let handle: OpaquePointer = try await invokeAsyncFunction { promise, context in
            asyncContext.withNativeHandle { asyncContext in
                connectionManager.withNativeHandle { connectionManager in
                    request.withNativeHandle { request in
                        signal_cdsi_lookup_new(promise, context, asyncContext, connectionManager, auth.username, auth.password, request, timeoutMs)
                    }
                }
            }
        }
        return CdsiLookup(native: handle, asyncContext: asyncContext)
    }

    private var asyncContext: TokioAsyncContext
    private var connectionManager: ConnectionManager
}

/// Authentication information used for connecting to CDSI servers.
///
/// This corresponds to the username/password pair provided by the chat service.
public struct Auth {
    public let username: String
    public let password: String
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}

public struct AciAndAccessKey {
    public let aci: Aci
    public let accessKey: Data
    public init(aci: Aci, accessKey: Data) {
        self.aci = aci
        self.accessKey = accessKey
    }
}

/// Information passed to the CDSI server when making a request.
public class CdsiLookupRequest: NativeHandleOwner {
    /// Indicates whether this request object was constructed with a token.
    public private(set) var hasToken: Bool = false

    private convenience init() {
        var handle: OpaquePointer?
        try! checkError(signal_lookup_request_new(&handle))
        self.init(owned: handle!)
    }

    /// Creates a new `CdsiLookupRequest` with the provided data.
    ///
    /// Phone numbers should be passed in as string-encoded numeric values,
    /// optionally with a leading `+` character.
    ///
    /// - Throws: a ``SignalError`` if any of the arguments are invalid,
    /// including the phone numbers or the access keys.
    public convenience init(
        e164s: [String],
        prevE164s: [String],
        acisAndAccessKeys: [AciAndAccessKey],
        token: Data?,
        returnAcisWithoutUaks: Bool) throws {
        self.init()
        try self.withNativeHandle { handle in
            for e164 in e164s {
                try checkError(signal_lookup_request_add_e164(handle, e164))
            }

            for prevE164 in prevE164s {
                try checkError(signal_lookup_request_add_previous_e164(handle, prevE164))
            }

            for aciAndAccessKey in acisAndAccessKeys {
                let aci = aciAndAccessKey.aci
                let accessKey = aciAndAccessKey.accessKey
                try aci.withPointerToFixedWidthBinary { aci in
                    try accessKey.withUnsafeBorrowedBuffer { accessKey in
                        try checkError(signal_lookup_request_add_aci_and_access_key(handle, aci, accessKey))
                    }
                }
            }

            if let token = token {
                try token.withUnsafeBorrowedBuffer { token in
                    try checkError(signal_lookup_request_set_token(handle, token))
                }
                self.hasToken = true
            }

            try checkError(signal_lookup_request_set_return_acis_without_uaks(handle, returnAcisWithoutUaks))
        }
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_lookup_request_destroy(handle)
    }
}

/// CDSI lookup in progress.
///
/// Returned by ``Net/cdsiLookup(auth:request:timeout:)`` when a request is successfully initiated.
public class CdsiLookup {
    class NativeCdsiLookup: NativeHandleOwner {
        internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
            signal_cdsi_lookup_destroy(handle)
        }
    }

    private var asyncContext: TokioAsyncContext
    private var native: NativeCdsiLookup

    internal init(native: OpaquePointer, asyncContext: TokioAsyncContext) {
        self.native = NativeCdsiLookup(owned: native)
        self.asyncContext = asyncContext
    }

    /// The token returned by the CDSI server.
    ///
    /// Clients can save this and pass it with future request to avoid getting
    /// "charged" for rate-limiting purposes for lookups of the same phone
    /// numbers.
    public var token: Data {
        failOnError {
            try native.withNativeHandle { handle in
              try invokeFnReturningData {
                  signal_cdsi_lookup_token($0, handle)
              }
            }
        }
    }

    /// Asynchronously waits for the request to complete and returns the response.
    ///
    /// After this method is called on a ``CdsiLookup`` object, the object
    /// should not be used again.
    ///
    /// - Returns: The collected data from the server.
    ///
    /// - Throws: ``SignalError`` if the request fails for any reason, including
    ///   `SignalError.networkError` for a network-level connectivity issue,
    ///   `SignalError.networkProtocolError` for a CDSI or attested connection protocol issue.
    public func complete() async throws -> CdsiLookupResponse {
        let response: SignalFfiCdsiLookupResponse = try await invokeAsyncFunction { promise, context in
            asyncContext.withNativeHandle { asyncContext in
                native.withNativeHandle { handle in
                    signal_cdsi_lookup_complete(promise, context, asyncContext, handle)
                }
            }
        }

        return CdsiLookupResponse(entries: LookupResponseEntryList(owned: response.entries), debugPermitsUsed: response.debug_permits_used)
    }
}

/// Response to the server produced by a completed ``CdsiLookup``.
///
/// Returned by ``CdsiLookup/complete()`` on success.
public struct CdsiLookupResponse {
    /// The entries received from the server.
    public let entries: LookupResponseEntryList
    /// How many "permits" were used in making the request.
    public let debugPermitsUsed: Int32
}

/// Entries received from the CDSI server in response to a lookup request.
///
/// Contains a sequence of ``CdsiLookupResponseEntry`` values. Conforms
/// to the `Collection` protocol to allow indexing and iteration over those
/// values.
public class LookupResponseEntryList: Collection {
    private var owned: UnsafeMutableBufferPointer<CdsiLookupResponseEntry>

    init(owned: SignalOwnedBufferOfFfiCdsiLookupResponseEntry) {
        self.owned = UnsafeMutableBufferPointer(start: owned.base, count: Int(owned.length))
    }

    deinit {
        signal_free_lookup_response_entry_list(SignalOwnedBufferOfFfiCdsiLookupResponseEntry(base: self.owned.baseAddress, length: self.owned.count))
    }

    public typealias Index = UnsafeMutableBufferPointer<CdsiLookupResponseEntry>.Index
    public typealias Element = UnsafeMutableBufferPointer<CdsiLookupResponseEntry>.Element
    public typealias SubSequence = UnsafeMutableBufferPointer<CdsiLookupResponseEntry>.SubSequence

    public var startIndex: Index { self.owned.startIndex }

    public var endIndex: Index { self.owned.endIndex }

    public func index(after: Index) -> Index {
        self.owned.index(after: after)
    }

    public subscript(position: Index) -> Element { self.owned[position] }
    public subscript(bounds: Range<Index>) -> SubSequence { self.owned[bounds] }
}

let nilUuid =  uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

/// Entry contained in a successful CDSI lookup response.
///
/// See ``CdsiLookupResponseEntryProtocol`` (which this type conforms to) for
/// getters for the various fields.
public typealias CdsiLookupResponseEntry = SignalFfiCdsiLookupResponseEntry

/// Getters for an entry in a CDSI lookup response.
public protocol CdsiLookupResponseEntryProtocol {
    /// The ACI in the response, if there was any.
    var aci: Aci? { get }
    /// The PNI in the response, if there was any.
    var pni: Pni? { get }
    /// The unformatted phone number for the entry.
    var e164: UInt64 { get }
}

extension CdsiLookupResponseEntry: CdsiLookupResponseEntryProtocol {
    public var aci: Aci? {
        let aciUuid = UUID(uuid: self.rawAciUuid)
        return aciUuid != UUID(uuid: nilUuid) ? Aci(fromUUID: aciUuid) : nil
    }

    public var pni: Pni? {
        let pniUuid = UUID(uuid: self.rawPniUuid)
        return pniUuid != UUID(uuid: nilUuid) ? Pni(fromUUID: pniUuid) : nil
    }

    init(e164: UInt64, _ aci: Aci?, _ pni: Pni?) {
        self.init(
            e164: e164,
            rawAciUuid: aci?.rawUUID.uuid ?? nilUuid,
            rawPniUuid: pni?.rawUUID.uuid ?? nilUuid
        )
    }
}

extension CdsiLookupResponseEntry: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.aci == rhs.aci && lhs.pni == rhs.pni && lhs.e164 == rhs.e164
    }
}

internal class TokioAsyncContext: NativeHandleOwner {
    convenience init() {
        var handle: OpaquePointer?
        failOnError(signal_tokio_async_context_new(&handle))
        self.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_tokio_async_context_destroy(handle)
    }
}

internal class ConnectionManager: NativeHandleOwner {
    convenience init(env: Net.Environment) {
        var handle: OpaquePointer?
        failOnError(signal_connection_manager_new(&handle, env.rawValue))
        self.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        signal_connection_manager_destroy(handle)
    }
}

func durationToMillis(_ interval: TimeInterval) -> UInt32 {
    let msDouble = interval * 1000
    return msDouble > Double(UInt32.max) ? UInt32.max : UInt32(msDouble)
}
