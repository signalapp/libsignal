//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum BackupLevel: UInt8 {
    // This must match the Rust version of the enum.
    case messages = 200, media = 201
}
