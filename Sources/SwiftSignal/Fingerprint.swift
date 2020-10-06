import SignalFfi
import Foundation

struct DisplayableFingerprint {
    let formatted: String

    internal init(formatted: String) {
        self.formatted = formatted
    }
}

struct ScannableFingerprint {
    let encoding: [UInt8]

    internal init(encoding: [UInt8]) {
        self.encoding = encoding
    }

    func compareWith(other: ScannableFingerprint) throws -> Bool {
        var result: Bool = false
        try CheckError(signal_fingerprint_compare(&result, encoding, encoding.count,
                                                  other.encoding, other.encoding.count))
        return result
    }
}

struct Fingerprint {
    let scannable : ScannableFingerprint
    let displayable: DisplayableFingerprint

    internal init(displayable: DisplayableFingerprint, scannable: ScannableFingerprint) {
        self.displayable = displayable
        self.scannable = scannable
    }
}

struct NumericFingerprintGenerator {
    private let iterations: Int

    init(iterations: Int) {
        self.iterations = iterations
    }

    func createFor(version: Int,
                   local_identifier: [UInt8],
                   local_key: PublicKey,
                   remote_identifier: [UInt8],
                   remote_key: PublicKey) throws -> Fingerprint {

    var obj : OpaquePointer?
    try CheckError(signal_fingerprint_new(&obj, UInt32(iterations), UInt32(version),
                                          local_identifier, local_identifier.count,
                                          local_key.nativeHandle(),
                                          remote_identifier, remote_identifier.count,
                                          remote_key.nativeHandle()))

    let fprint_str = try invokeFnReturningString(fn: { (b) in signal_fingerprint_display_string(obj, b) })
    let displayable = DisplayableFingerprint(formatted: fprint_str)

    let scannable_bits = try invokeFnReturningArray(fn: { (b,bl) in signal_fingerprint_scannable_encoding(obj, b, bl) })
    let scannable = ScannableFingerprint(encoding: scannable_bits)
    try CheckError(signal_fingerprint_destroy(obj))

    return Fingerprint(displayable: displayable, scannable: scannable)
    }
}
