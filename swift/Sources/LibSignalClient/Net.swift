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
    public enum Environment: UInt8, Sendable {
        // This needs to be kept in sync with the Rust version of the enum.

        /// Signal's staging environment.
        case staging = 0

        /// Signal's production environment.
        case production = 1
    }

    /// The "scheme" for Signal TLS proxies. See ``Net/setProxy(scheme:host:port:username:password:)``.
    public static let signalTlsProxyScheme = "org.signal.tls"

    /// Creates a new `Net` instance that enables interacting with services in the given Signal environment.
    public init(env: Environment, userAgent: String) {
        self.asyncContext = TokioAsyncContext()
        self.connectionManager = ConnectionManager(env: env, userAgent: userAgent)
    }

    /// Sets the proxy host to be used for all new connections (until overridden).
    ///
    /// Sets a server to be used to proxy all new outgoing connections. The proxy can be
    /// overridden by calling this method again or unset by calling ``Net/clearProxy()``.
    /// Passing `nil` for the `port` means the default port for the scheme will be used.
    ///
    /// To specify a Signal transparent TLS proxy, use ``Net/signalTlsProxyScheme``,
    /// or the overload that takes a separate domain and port number.
    ///
    /// Existing connections and services will continue with the setting they were created with.
    /// (In particular, changing this setting will not affect any existing ``ChatService``s.)
    ///
    /// - Throws: if the scheme is unsupported or if the provided parameters are invalid for that scheme
    ///   (e.g. Signal TLS proxies don't support authentication)
    public func setProxy(scheme: String, host: String, port: UInt16? = nil, username: String? = nil, password: String? = nil) throws {
        try self.connectionManager.setProxy(scheme: scheme, host: host, port: port, username: username, password: password)
    }

    /// Sets the Signal TLS proxy host to be used for all new connections (until overridden).
    ///
    /// Sets a domain name and port to be used to proxy all new outgoing connections, using a Signal
    /// transparent TLS proxy. The proxy can be overridden by calling this method again or unset by
    /// calling ``Net/clearProxy()``.
    ///
    /// Existing connections and services will continue with the setting they were created with.
    /// (In particular, changing this setting will not affect any existing ``ChatConnection``s.)
    ///
    /// - Throws: if the host or port is not structurally valid, such as a port of 0.
    public func setProxy(host: String, port: UInt16?) throws {
        // Support <username>@<host> syntax to allow UNENCRYPTED_FOR_TESTING as a marker user.
        // This is not a stable feature of the API and may go away in the future;
        // the Rust layer will reject any other users anyway. But it's convenient for us.
        let (username, host): (String?, String) = if let atSign = host.firstIndex(of: "@") {
            (String(host[..<atSign]), String(host[atSign...].dropFirst()))
        } else {
            (nil, host)
        }

        try self.connectionManager.setProxy(scheme: Net.signalTlsProxyScheme, host: host, port: port, username: username, password: nil)
    }

    /// Refuses to make any new connections until a new proxy configuration is set or
    /// ``Net/clearProxy()`` is called.
    ///
    /// Existing connections will not be affected.
    public func setInvalidProxy() {
        self.connectionManager.setInvalidProxy()
    }

    /// Clears the proxy host (if any) so that future connections will be made directly.
    ///
    /// Clears any proxy configuration set via ``Net/setProxy(host:port:)`` or
    /// ``Net/setInvalidProxy()``. If none was set, calling this method is a no-op.
    ///
    /// Existing connections and services will continue with the setting they were created with.
    /// (In particular, changing this setting will not affect any existing ``ChatConnection``s.)
    public func clearProxy() {
        self.connectionManager.clearProxy()
    }

    /// Enables or disables censorship circumvention for all new connections (until changed).
    ///
    /// If CC is enabled, *new* connections and services may try additional routes to the Signal servers.
    /// Existing connections and services will continue with the setting they were created with.
    /// (In particular, changing this setting will not affect any existing ``ChatConnection``s.)
    ///
    /// CC is off by default.
    public func setCensorshipCircumventionEnabled(_ enabled: Bool) {
        self.connectionManager.setCensorshipCircumventionEnabled(enabled)
    }

    /// Notifies libsignal that the network has changed.
    ///
    /// This will lead to, e.g. caches being cleared and cooldowns being reset.
    ///
    /// No errors are expected to be thrown; this is only to make programmer errors
    /// recoverable for this particular call.
    public func networkDidChange() throws {
        try self.connectionManager.withNativeHandle { connectionManager in
            try checkError(signal_connection_manager_on_network_change(connectionManager.const()))
        }
    }

    /// Like ``cdsiLookup(auth:request:)`` but with the parameters to ``CdsiLookupRequest`` broken out.
    public func cdsiLookup(
        auth: Auth,
        prevE164s: [String],
        e164s: [String],
        acisAndAccessKeys: [AciAndAccessKey],
        token: Data?,
        useNewConnectLogic: Bool = false
    ) async throws -> CdsiLookup {
        let request = try CdsiLookupRequest(e164s: e164s, prevE164s: prevE164s, acisAndAccessKeys: acisAndAccessKeys, token: token)
        return try await self.cdsiLookup(auth: auth, request: request, useNewConnectLogic: useNewConnectLogic)
    }

    @available(*, deprecated, message: "returnAcisWithoutUaks is deprecated; use the overload that does not have it as an argument")
    public func cdsiLookup(
        auth: Auth,
        prevE164s: [String],
        e164s: [String],
        acisAndAccessKeys: [AciAndAccessKey],
        returnAcisWithoutUaks: Bool,
        token: Data?
    ) async throws -> CdsiLookup {
        return try await self.cdsiLookup(auth: auth, prevE164s: prevE164s, e164s: e164s, acisAndAccessKeys: acisAndAccessKeys, token: token)
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
    ///   - useNewConnectLogic: Whether to use the newer logic for establishing the connection used for the request.
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
    /// let lookup = try await net.cdsiLookup(auth: auth, request: request)
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
        useNewConnectLogic: Bool = false
    ) async throws -> CdsiLookup {
        let create_lookup = useNewConnectLogic ? signal_cdsi_lookup_new_routes : signal_cdsi_lookup_new
        let handle = try await self.asyncContext.invokeAsyncFunction { promise, asyncContext in
            self.connectionManager.withNativeHandle { connectionManager in
                request.withNativeHandle { request in
                    create_lookup(promise, asyncContext.const(), connectionManager.const(), auth.username, auth.password, request.const())
                }
            }
        }
        return CdsiLookup(native: NonNull(handle)!, asyncContext: self.asyncContext)
    }

    /// Asynchronously establishes an authenticated connection to the remote
    /// chat service.
    ///
    /// Creates a connection to the remote chat service, or throws a
    /// ``SignalError`` if one cannot be established, or if the connection
    /// attempt is rejected. Once the connection is established, the returned
    /// object can be used to send and receive messages after
    /// ``AuthenticatedChatConnection/start(listener:)`` is called.
    ///
    /// - Parameters:
    ///   - username: The username to provide; this is typically of the form `{aci}.{deviceId}`.
    ///   - password: The password to provide to the server.
    ///   - receiveStories: Indicates to the server whether it should send story updates on this connection.
    ///
    /// - Throws: ``SignalError/appExpired(_:)`` if the current app version is too old (as judged by
    ///   the server).
    /// - Throws: ``SignalError/rateLimitedError(_:, _:)`` if the server
    ///   response indicates the request should be tried again after some time.
    /// - Throws: ``SignalError/deviceDeregistered(_:)`` if the server response
    ///   indicates the device is no longer registered.
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    ///
    /// - Returns:
    ///   An object representing the established, but not yet active, connection.
    public func connectAuthenticatedChat(username: String, password: String, receiveStories: Bool) async throws -> AuthenticatedChatConnection {
        return try await AuthenticatedChatConnection(tokioAsyncContext: self.asyncContext, connectionManager: self.connectionManager, username: username, password: password, receiveStories: receiveStories)
    }

    /// Asynchronously establishes an unauthenticated connection to the remote
    /// chat service.
    ///
    /// Creates a connection to the remote chat service, or throws a
    /// ``SignalError`` if one cannot be established, or if the connection
    /// attempt is rejected. Once the connection is established, the returned
    /// object can be used to send and receive messages after
    /// ``UnauthenticatedChatConnection/start(listener:)`` is called.
    ///
    /// - Throws: ``SignalError/appExpired(_:)`` if the current app version is too old (as judged by
    ///   the server).
    /// - Throws: ``SignalError/rateLimitedError(_:, _:)`` if the server
    ///   response indicates the request should be tried again after some time.
    /// - Throws: Other ``SignalError``s for other kinds of failures.
    ///
    /// - Returns:
    ///   An object representing the established, but not active, connection.
    public func connectUnauthenticatedChat() async throws -> UnauthenticatedChatConnection {
        return try await UnauthenticatedChatConnection(tokioAsyncContext: self.asyncContext, connectionManager: self.connectionManager)
    }

    private var asyncContext: TokioAsyncContext
    /// Exposed for testing.
    internal var connectionManager: ConnectionManager
}

/// Authentication information used for connecting to CDS and SVR servers.
///
/// This corresponds to the username/password pair provided by the chat service.
public struct Auth: Sendable {
    public let username: String
    public let password: String
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}

extension Auth {
    // To be used by the tests
    internal init(username: String, enclaveSecret: String) throws {
        let otp = try invokeFnReturningString {
            signal_create_otp_from_base64($0, username, enclaveSecret)
        }
        self.init(username: username, password: otp)
    }
}

internal class ConnectionManager: NativeHandleOwner<SignalMutPointerConnectionManager> {
    private class ProxyConfig: NativeHandleOwner<SignalMutPointerConnectionProxyConfig> {
        override class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerConnectionProxyConfig>) -> SignalFfiErrorRef? {
            signal_connection_proxy_config_destroy(handle.pointer)
        }
    }

    convenience init(env: Net.Environment, userAgent: String) {
        var handle = SignalMutPointerConnectionManager()
        failOnError(signal_connection_manager_new(&handle, env.rawValue, userAgent))
        self.init(owned: NonNull(handle)!)
    }

    internal func setProxy(scheme: String, host: String, port: UInt16?, username: String?, password: String?) throws {
        // We have to cast to Int32 because of how the port number is validated...for Java.
        // But it also lets us distinguish "no port provided".
        let port = port.map(Int32.init) ?? .min

        do {
            let proxyConfig: ProxyConfig = try username.withCString { username in
                try password.withCString { password in
                    try invokeFnReturningNativeHandle {
                        signal_connection_proxy_config_new($0, scheme, host, port, username, password)
                    }
                }
            }

            try proxyConfig.withNativeHandle { proxyConfig in
                try self.withNativeHandle {
                    try checkError(signal_connection_manager_set_proxy($0.const(), proxyConfig.const()))
                }
            }
        } catch {
            self.setInvalidProxy()
            throw error
        }
    }

    internal func setInvalidProxy() {
        self.withNativeHandle {
            failOnError(signal_connection_manager_set_invalid_proxy($0.const()))
        }
    }

    internal func clearProxy() {
        self.withNativeHandle {
            failOnError(signal_connection_manager_clear_proxy($0.const()))
        }
    }

    internal func setCensorshipCircumventionEnabled(_ enabled: Bool) {
        self.withNativeHandle {
            failOnError(signal_connection_manager_set_censorship_circumvention_enabled($0.const(), enabled))
        }
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerConnectionManager>) -> SignalFfiErrorRef? {
        signal_connection_manager_destroy(handle.pointer)
    }
}

extension SignalMutPointerConnectionManager: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerConnectionManager

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

extension SignalConstPointerConnectionManager: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension SignalMutPointerConnectionProxyConfig: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerConnectionProxyConfig

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

extension SignalConstPointerConnectionProxyConfig: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
