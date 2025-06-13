//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GenericServerPublicParams: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_generic_server_public_params_check_valid_contents)
    }
}
