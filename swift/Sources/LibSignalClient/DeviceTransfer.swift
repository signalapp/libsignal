//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public struct DeviceTransferKey {
    public let privateKey: [UInt8]

    public static func generate() -> Self {
        let privateKey = failOnError {
            try invokeFnReturningArray {
                signal_device_transfer_generate_private_key($0, $1)
            }
        }

        return Self(privateKey: privateKey)
    }

    public func privateKeyMaterial() -> [UInt8] {
        return self.privateKey
    }

    public func generateCertificate(_ name: String, _ daysTilExpire: Int) -> [UInt8] {
        return privateKey.withUnsafeBorrowedBuffer { privateKeyBuffer in
            failOnError {
                try invokeFnReturningArray {
                    signal_device_transfer_generate_certificate($0, $1,
                                                                privateKeyBuffer,
                                                                name,
                                                                UInt32(daysTilExpire))
                }
            }
        }
    }
}
