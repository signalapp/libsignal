//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum KeyFormat: UInt8, CaseIterable, Sendable {
    // PKCS#8 is the default for backward compatibility
    case pkcs8 = 0
    case keySpecific = 1
}

public struct DeviceTransferKey: Sendable {
    public let privateKey: [UInt8]

    public static func generate(formattedAs keyFormat: KeyFormat = .pkcs8) -> Self {
        let privateKey = failOnError {
            try invokeFnReturningArray {
                signal_device_transfer_generate_private_key_with_format($0, keyFormat.rawValue)
            }
        }

        return Self(privateKey: privateKey)
    }

    public func privateKeyMaterial() -> [UInt8] {
        return self.privateKey
    }

    public func generateCertificate(_ name: String, _ daysTilExpire: Int) -> [UInt8] {
        return self.privateKey.withUnsafeBorrowedBuffer { privateKeyBuffer in
            failOnError {
                try invokeFnReturningArray {
                    signal_device_transfer_generate_certificate(
                        $0,
                        privateKeyBuffer,
                        name,
                        UInt32(daysTilExpire)
                    )
                }
            }
        }
    }
}
