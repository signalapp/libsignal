//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public struct UploadForm: Equatable, Sendable {
    public var cdn: UInt32
    public var key: String
    public var headers: [String: String]
    public var signedUploadUrl: URL

    public init(cdn: UInt32, key: String, headers: [String: String], signedUploadUrl: URL) {
        self.cdn = cdn
        self.key = key
        self.headers = headers
        self.signedUploadUrl = signedUploadUrl
    }

    internal init(consuming raw: SignalFfiUploadForm) throws {
        var raw = raw
        defer { raw.free() }
        self.cdn = raw.cdn
        self.key = String(cString: raw.key)
        guard let signedUploadUrl = URL(string: String(cString: raw.signed_upload_url)) else {
            throw SignalError.networkProtocolError("Invalid URL for UploadForm's signedUploadUrl")
        }
        self.signedUploadUrl = signedUploadUrl
        let header_keys = UnsafeBufferPointer(start: raw.header_keys.base, count: raw.header_keys.length)
        let header_values = UnsafeBufferPointer(start: raw.header_values.base, count: raw.header_values.length)
        if header_keys.count != header_values.count {
            fatalError("Rust didn't give us matching keys and values")
        }
        self.headers = [:]
        for (k, v) in zip(
            header_keys.lazy.map { String(cString: $0!) },
            header_values.lazy.map { String(cString: $0!) },
        ) {
            self.headers[k] = v
        }
    }
}

extension SignalFfiUploadForm {
    /// Assumes the response was created from Rust, and frees all the members.
    ///
    /// Do not use the response after this!
    internal mutating func free() {
        signal_free_string(self.key)
        signal_free_string(self.signed_upload_url)
        signal_free_list_of_strings(self.header_keys)
        signal_free_list_of_strings(self.header_values)
        // Zero out all the fields to be sure they won't be reused.
        self = .init()
    }
}
