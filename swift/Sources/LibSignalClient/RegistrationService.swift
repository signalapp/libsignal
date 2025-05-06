//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum RegistrationError: Error {
    case invalidSessionId(String)
    case requestNotValid(String)
    case unknown(String)
}
