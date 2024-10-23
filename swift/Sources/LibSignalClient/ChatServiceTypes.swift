//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum IpType: UInt8, Sendable {
    // Must be kept in sync with libsignal-net's IpType.
    case unknown, ipv4, ipv6
}

public struct ChatRequest: Equatable, Sendable {
    public var method: String
    public var pathAndQuery: String
    public var headers: [String: String]
    public var body: Data?
    public var timeout: TimeInterval

    public init(method: String, pathAndQuery: String, headers: [String: String] = [:], body: Data? = nil, timeout: TimeInterval) {
        self.method = method
        self.pathAndQuery = pathAndQuery
        self.headers = headers
        self.body = body
        self.timeout = timeout
    }

    internal var timeoutMillis: UInt32 {
        let timeoutMillisFloat: Double = 1000 * self.timeout
        if timeoutMillisFloat > Double(UInt32.max) {
            return .max
        } else if timeoutMillisFloat < 0 {
            // A bad idea, but one that won't crash.
            return 0
        } else {
            return UInt32(timeoutMillisFloat)
        }
    }

    // Exposed for testing
    internal class InternalRequest: NativeHandleOwner {
        convenience init(_ request: ChatRequest) throws {
            var handle: OpaquePointer?
            if let body = request.body {
                try body.withUnsafeBorrowedBuffer { body in
                    try checkError(signal_http_request_new_with_body(&handle, request.method, request.pathAndQuery, body))
                }
            } else {
                try checkError(signal_http_request_new_without_body(&handle, request.method, request.pathAndQuery))
            }
            // Make sure we clean up the handle if there are any errors adding headers.
            self.init(owned: handle!)

            for (name, value) in request.headers {
                try checkError(signal_http_request_add_header(handle, name, value))
            }
        }

        override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
            return signal_http_request_destroy(handle)
        }
    }
}

public struct ChatResponse: Equatable, Sendable {
    public var status: UInt16
    public var message: String
    public var headers: [String: String]
    public var body: Data

    public init(status: UInt16, message: String = "", headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.message = message
        self.headers = headers
        self.body = body
    }

    // Exposed for testing.
    internal init(consuming rawResponse: SignalFfiChatResponse) throws {
        var rawResponse = rawResponse

        self.status = rawResponse.status
        self.message = String(cString: rawResponse.message)
        self.headers = Dictionary(uniqueKeysWithValues: rawResponse.rawHeadersAsBuffer.lazy.map { (rawHeader: UnsafePointer<CChar>?) -> (String, String) in
            guard let rawHeader else {
                fatalError("null in headers list")
            }
            let asciiColon = Int32(Character(":").asciiValue!)
            guard let colonPtr = strchr(rawHeader, asciiColon) else {
                fatalError("header returned without colon")
            }
            let nameCount = UnsafePointer(colonPtr) - rawHeader
            guard let name = UnsafeBufferPointer(start: rawHeader, count: nameCount).withMemoryRebound(to: UInt8.self, {
                String(bytes: $0, encoding: .utf8)
            }) else {
                fatalError("non-UTF-8 header name not rejected by Rust")
            }
            let value = String(cString: colonPtr + 1)
            return (name, value)
        })

        // Avoid copying the body when possible!
        self.body = Data(bytesNoCopy: rawResponse.body.base, count: rawResponse.body.length, deallocator: .custom { base, length in
            signal_free_buffer(base, length)
        })
        // Clear it out so it doesn't get freed eagerly.
        rawResponse.body = .init()

        rawResponse.free()
    }
}

public struct ChatServiceDebugInfo: Equatable, Sendable {
    public var ipType: IpType
    public var duration: TimeInterval
    public var connectionInfo: String

    public init(ipType: IpType, duration: TimeInterval, connectionInfo: String) {
        self.ipType = ipType
        self.duration = duration
        self.connectionInfo = connectionInfo
    }

    internal init(consuming rawDebugInfo: SignalFfiChatServiceDebugInfo) {
        var rawDebugInfo = rawDebugInfo
        defer { rawDebugInfo.free() }
        self.ipType = IpType(rawValue: rawDebugInfo.raw_ip_type) ?? .unknown
        self.duration = rawDebugInfo.duration_secs
        self.connectionInfo = String(cString: rawDebugInfo.connection_info)
    }
}

extension SignalFfiChatResponse {
    fileprivate var rawHeadersAsBuffer: UnsafeBufferPointer<UnsafePointer<CChar>?> {
        .init(start: self.headers.base, count: self.headers.length)
    }

    /// Assumes the response was created from Rust, and frees all the members.
    ///
    /// Do not use the response after this!
    internal mutating func free() {
        signal_free_string(message)
        signal_free_list_of_strings(headers)
        signal_free_buffer(body.base, body.length)
        // Zero out all the fields to be sure they won't be reused.
        self = .init()
    }
}

extension SignalFfiChatServiceDebugInfo {
    fileprivate mutating func free() {
        signal_free_string(connection_info)
        // Zero out all the fields to be sure they won't be reused.
        self = .init()
    }
}
