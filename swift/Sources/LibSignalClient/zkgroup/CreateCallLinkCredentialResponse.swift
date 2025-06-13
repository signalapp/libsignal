//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class CreateCallLinkCredentialResponse: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_create_call_link_credential_response_check_valid_contents)
    }
}
