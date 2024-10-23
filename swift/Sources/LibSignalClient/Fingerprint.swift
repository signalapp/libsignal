//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public struct DisplayableFingerprint: Sendable {
    public let formatted: String
}

public struct ScannableFingerprint: Sendable {
    public let encoding: [UInt8]

    /// Returns `true` if this fingerprint matches the fingerprint encoding `other`, `false` if not.
    ///
    /// Throws an error if `other` is not a valid fingerprint encoding, or if it uses an
    /// incompatible encoding version.
    public func compare<Other: ContiguousBytes>(againstEncoding other: Other) throws -> Bool {
        var result = false
        try encoding.withUnsafeBorrowedBuffer { encodingBuffer in
            try other.withUnsafeBorrowedBuffer { otherBuffer in
                try checkError(signal_fingerprint_compare(&result, encodingBuffer, otherBuffer))
            }
        }
        return result
    }
}

public struct Fingerprint: Sendable {
    public let scannable: ScannableFingerprint
    public let displayable: DisplayableFingerprint

    internal init(displayable: DisplayableFingerprint, scannable: ScannableFingerprint) {
        self.displayable = displayable
        self.scannable = scannable
    }
}

public struct NumericFingerprintGenerator: Sendable {
    private let iterations: Int

    public init(iterations: Int) {
        self.iterations = iterations
    }

    public func create(
        version: Int,
        localIdentifier: some ContiguousBytes,
        localKey: PublicKey,
        remoteIdentifier: some ContiguousBytes,
        remoteKey: PublicKey
    ) throws -> Fingerprint {
        var obj: OpaquePointer?
        try withNativeHandles(localKey, remoteKey) { localKeyHandle, remoteKeyHandle in
            try localIdentifier.withUnsafeBorrowedBuffer { localBuffer in
                try remoteIdentifier.withUnsafeBorrowedBuffer { remoteBuffer in
                    try checkError(signal_fingerprint_new(
                        &obj,
                        UInt32(self.iterations),
                        UInt32(version),
                        localBuffer,
                        localKeyHandle,
                        remoteBuffer,
                        remoteKeyHandle
                    ))
                }
            }
        }

        let fprintStr = try invokeFnReturningString {
            signal_fingerprint_display_string($0, obj)
        }
        let displayable = DisplayableFingerprint(formatted: fprintStr)

        let scannableBits = try invokeFnReturningArray {
            signal_fingerprint_scannable_encoding($0, obj)
        }
        let scannable = ScannableFingerprint(encoding: scannableBits)
        try checkError(signal_fingerprint_destroy(obj))

        return Fingerprint(displayable: displayable, scannable: scannable)
    }
}
