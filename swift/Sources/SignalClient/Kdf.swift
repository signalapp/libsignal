//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public func hkdf<InputBytes, SaltBytes, InfoBytes>(outputLength: Int,
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
                                                  inputBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), inputBytes.count,
                                                  infoBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), infoBytes.count,
                                                  saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), saltBytes.count))
            }
        }
    }

    return output
}

@available(*, deprecated, message: "Remove the 'version' parameter for standard HKDF behavior")
public func hkdf<InputBytes, SaltBytes, InfoBytes>(outputLength: Int,
                                                   version: UInt32,
                                                   inputKeyMaterial: InputBytes,
                                                   salt: SaltBytes,
                                                   info: InfoBytes) throws -> [UInt8]
where InputBytes: ContiguousBytes, SaltBytes: ContiguousBytes, InfoBytes: ContiguousBytes {
    precondition(version == 3, "HKDF versions other than 3 are no longer supported")
    return try hkdf(outputLength: outputLength,
                    inputKeyMaterial: inputKeyMaterial,
                    salt: salt,
                    info: info)
}
