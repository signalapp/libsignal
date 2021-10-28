//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerZkAuthOperations {

  let serverSecretParams: ServerSecretParams

  public init(serverSecretParams: ServerSecretParams) {
    self.serverSecretParams = serverSecretParams
  }

  public func issueAuthCredential(uuid: UUID, redemptionTime: UInt32) throws -> AuthCredentialResponse {
    return try issueAuthCredential(randomness: Randomness.generate(), uuid: uuid, redemptionTime: redemptionTime)
  }

  public func issueAuthCredential(randomness: Randomness, uuid: UUID, redemptionTime: UInt32) throws -> AuthCredentialResponse {
    return try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try withUnsafePointer(to: uuid.uuid) { uuid in
          try invokeFnReturningSerialized {
            signal_server_secret_params_issue_auth_credential_deterministic($0, serverSecretParams, randomness, uuid, redemptionTime)
          }
        }
      }
    }
  }

  public func verifyAuthCredentialPresentation(groupPublicParams: GroupPublicParams, authCredentialPresentation: AuthCredentialPresentation) throws {
    try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try groupPublicParams.withUnsafePointerToSerialized { groupPublicParams in
        try authCredentialPresentation.withUnsafePointerToSerialized { authCredentialPresentation in
          try checkError(signal_server_secret_params_verify_auth_credential_presentation(serverSecretParams, groupPublicParams, authCredentialPresentation))
        }
      }
    }
  }

}
