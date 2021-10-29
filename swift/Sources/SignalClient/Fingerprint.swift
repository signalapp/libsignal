//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public struct DisplayableFingerprint {
    public let formatted: String

    internal init(formatted: String) {
        self.formatted = formatted
    }
}

public struct ScannableFingerprint {
    public let encoding: [UInt8]

    internal init(encoding: [UInt8]) {
        self.encoding = encoding
    }

    public func compare(against other: ScannableFingerprint) throws -> Bool {
        var result: Bool = false
        try checkError(signal_fingerprint_compare(&result, encoding, encoding.count,
                                                  other.encoding, other.encoding.count))
        return result
    }
}

public struct Fingerprint {
    public let scannable: ScannableFingerprint
    public let displayable: DisplayableFingerprint

    internal init(displayable: DisplayableFingerprint, scannable: ScannableFingerprint) {
        self.displayable = displayable
        self.scannable = scannable
    }
}

public struct NumericFingerprintGenerator {
    private let iterations: Int

    public init(iterations: Int) {
        self.iterations = iterations
    }

    public func create<LocalBytes, RemoteBytes>(version: Int,
                                                localIdentifier: LocalBytes,
                                                localKey: PublicKey,
                                                remoteIdentifier: RemoteBytes,
                                                remoteKey: PublicKey) throws -> Fingerprint
    where LocalBytes: ContiguousBytes, RemoteBytes: ContiguousBytes {
        var obj: OpaquePointer?
        try withNativeHandles(localKey, remoteKey) { localKeyHandle, remoteKeyHandle in
            try localIdentifier.withUnsafeBytes { localBytes in
                try remoteIdentifier.withUnsafeBytes { remoteBytes in
                    try checkError(signal_fingerprint_new(&obj, UInt32(iterations), UInt32(version),
                                                          localBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), localBytes.count,
                                                          localKeyHandle,
                                                          remoteBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), remoteBytes.count,
                                                          remoteKeyHandle))
                }
            }
        }

        let fprintStr = try invokeFnReturningString {
            signal_fingerprint_display_string($0, obj)
        }
        let displayable = DisplayableFingerprint(formatted: fprintStr)

        let scannableBits = try invokeFnReturningArray {
            signal_fingerprint_scannable_encoding($0, $1, obj)
        }
        let scannable = ScannableFingerprint(encoding: scannableBits)
        try checkError(signal_fingerprint_destroy(obj))

        return Fingerprint(displayable: displayable, scannable: scannable)
    }
}
