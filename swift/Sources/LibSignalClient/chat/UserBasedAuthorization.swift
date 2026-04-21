//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public enum UserBasedAuthorization: Sendable {
    case accessKey(Data)
    case groupSend(GroupSendFullToken)
    case unrestrictedUnauthenticatedAccess
}
