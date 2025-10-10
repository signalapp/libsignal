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
    public let encoding: Data

    /// Returns `true` if this fingerprint matches the fingerprint encoding `other`, `false` if not.
    ///
    /// Throws an error if `other` is not a valid fingerprint encoding, or if it uses an
    /// incompatible encoding version.
    public func compare<Other: ContiguousBytes>(againstEncoding other: Other) throws -> Bool {
        return try encoding.withUnsafeBorrowedBuffer { encodingBuffer in
            try other.withUnsafeBorrowedBuffer { otherBuffer in
                try invokeFnReturningBool {
                    signal_fingerprint_compare($0, encodingBuffer, otherBuffer)
                }
            }
        }
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
        let obj = try withAllBorrowed(
            localKey,
            remoteKey,
            .bytes(localIdentifier),
            .bytes(remoteIdentifier)
        ) { localKeyHandle, remoteKeyHandle, localBuffer, remoteBuffer in
            try invokeFnReturningValueByPointer(.init()) {
                signal_fingerprint_new(
                    $0,
                    UInt32(self.iterations),
                    UInt32(version),
                    localBuffer,
                    localKeyHandle.const(),
                    remoteBuffer,
                    remoteKeyHandle.const()
                )
            }
        }

        let fprintStr = try invokeFnReturningString {
            signal_fingerprint_display_string($0, obj.const())
        }
        let displayable = DisplayableFingerprint(formatted: fprintStr)

        let scannableBits = try invokeFnReturningData {
            signal_fingerprint_scannable_encoding($0, obj.const())
        }
        let scannable = ScannableFingerprint(encoding: scannableBits)
        try checkError(signal_fingerprint_destroy(obj))

        return Fingerprint(displayable: displayable, scannable: scannable)
    }
}

extension SignalMutPointerFingerprint: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerFingerprint

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

extension SignalConstPointerFingerprint: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
