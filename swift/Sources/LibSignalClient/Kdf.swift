//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public func hkdf(
    outputLength: Int,
    inputKeyMaterial: some ContiguousBytes,
    salt: some ContiguousBytes,
    info: some ContiguousBytes
) throws -> Data {
    var output = Data(count: outputLength)

    try output.withUnsafeMutableBytes { outputBuffer in
        try inputKeyMaterial.withUnsafeBorrowedBuffer { inputBuffer in
            try salt.withUnsafeBorrowedBuffer { saltBuffer in
                try info.withUnsafeBorrowedBuffer { infoBuffer in
                    try checkError(
                        signal_hkdf_derive(
                            .init(outputBuffer),
                            inputBuffer,
                            infoBuffer,
                            saltBuffer
                        )
                    )
                }
            }
        }
    }

    return output
}
