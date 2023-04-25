//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GenericServerSecretParams: ByteArray {

  public static func generate() -> Self {
    return failOnError {
      generate(randomness: try .generate())
    }
  }

  public static func generate(randomness: Randomness) -> Self {
    return failOnError {
      try randomness.withUnsafePointerToBytes { randomness in
        try invokeFnReturningVariableLengthSerialized {
          signal_generic_server_secret_params_generate_deterministic($0, randomness)
        }
      }
    }
  }

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_generic_server_secret_params_check_valid_contents)
  }

  public func getPublicParams() -> GenericServerPublicParams {
    return failOnError {
      try withUnsafeBorrowedBuffer { contents in
        try invokeFnReturningVariableLengthSerialized {
          signal_generic_server_secret_params_get_public_params($0, contents)
        }
      }
    }
  }

}
