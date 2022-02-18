//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerSecretParams: ByteArray {

  public static func generate() throws -> ServerSecretParams {
    return try generate(randomness: Randomness.generate())
  }

  public static func generate(randomness: Randomness) throws -> ServerSecretParams {
    return try randomness.withUnsafePointerToBytes { randomness in
      try invokeFnReturningSerialized {
        signal_server_secret_params_generate_deterministic($0, randomness)
      }
    }
  }

  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_server_secret_params_check_valid_contents)
  }

  public func getPublicParams() throws -> ServerPublicParams {
    return try withUnsafePointerToSerialized { contents in
      try invokeFnReturningSerialized {
        signal_server_secret_params_get_public_params($0, contents)
      }
    }
  }

  public func sign(message: [UInt8]) throws -> NotarySignature {
    return try sign(randomness: Randomness.generate(), message: message)
  }

  public func sign(randomness: Randomness, message: [UInt8]) throws -> NotarySignature {
    return try withUnsafePointerToSerialized { contents in
      try randomness.withUnsafePointerToBytes { randomness in
        try message.withUnsafeBorrowedBuffer { message in
          try invokeFnReturningSerialized {
            signal_server_secret_params_sign_deterministic($0, contents, randomness, message)
          }
        }
      }
    }
  }

}
