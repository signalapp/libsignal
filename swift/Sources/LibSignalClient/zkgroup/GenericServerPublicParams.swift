//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GenericServerPublicParams: ByteArray {
  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_generic_server_public_params_check_valid_contents)
  }
}
