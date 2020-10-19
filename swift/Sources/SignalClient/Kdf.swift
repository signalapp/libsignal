import SignalFfi
import Foundation

public func hkdf<InputBytes, SaltBytes, InfoBytes>(outputLength: Int,
                                                   version: UInt32,
                                                   inputKeyMaterial: InputBytes,
                                                   salt: SaltBytes,
                                                   info: InfoBytes) throws -> [UInt8]
where InputBytes: ContiguousBytes, SaltBytes: ContiguousBytes, InfoBytes: ContiguousBytes {
    var output = Array(repeating: UInt8(0x00), count: outputLength)

    try inputKeyMaterial.withUnsafeBytes { inputBytes in
        try salt.withUnsafeBytes { saltBytes in
            try info.withUnsafeBytes { infoBytes in
                try checkError(signal_hkdf_derive(&output,
                                                  outputLength,
                                                  Int32(version),
                                                  inputBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), inputBytes.count,
                                                  saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), saltBytes.count,
                                                  infoBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), infoBytes.count))
            }
        }
    }

    return output
}
