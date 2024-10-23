//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum BackupLevel: UInt8, Sendable {
    // This must match the Rust version of the enum.
    case free = 200, paid = 201
}

public enum BackupCredentialType: UInt8 {
    // This must match the Rust version of the enum.
    case messages = 1, media = 2
}
