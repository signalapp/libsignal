import SignalFfi

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

    public func create(version: Int,
                       localIdentifier: [UInt8],
                       localKey: PublicKey,
                       remoteIdentifier: [UInt8],
                       remoteKey: PublicKey) throws -> Fingerprint {

        var obj: OpaquePointer?
        try checkError(signal_fingerprint_new(&obj, UInt32(iterations), UInt32(version),
                                              localIdentifier, localIdentifier.count,
                                              localKey.nativeHandle,
                                              remoteIdentifier, remoteIdentifier.count,
                                              remoteKey.nativeHandle))

        let fprintStr = try invokeFnReturningString {
            signal_fingerprint_display_string(obj, $0)
        }
        let displayable = DisplayableFingerprint(formatted: fprintStr)

        let scannableBits = try invokeFnReturningArray {
            signal_fingerprint_scannable_encoding(obj, $0, $1)
        }
        let scannable = ScannableFingerprint(encoding: scannableBits)
        try checkError(signal_fingerprint_destroy(obj))

        return Fingerprint(displayable: displayable, scannable: scannable)
    }
}
