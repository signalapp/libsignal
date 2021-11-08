//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ClientZkAuthOperations {

  let serverPublicParams: ServerPublicParams

  public init(serverPublicParams: ServerPublicParams) {
    self.serverPublicParams = serverPublicParams
  }

  public func receiveAuthCredential(uuid: UUID, redemptionTime: UInt32, authCredentialResponse: AuthCredentialResponse) throws -> AuthCredential {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try withUnsafePointer(to: uuid.uuid) { uuid in
        try authCredentialResponse.withUnsafePointerToSerialized { authCredentialResponse in
          try invokeFnReturningSerialized {
            signal_server_public_params_receive_auth_credential($0, serverPublicParams, uuid, redemptionTime, authCredentialResponse)
          }
        }
      }
    }
  }

  public func createAuthCredentialPresentation(groupSecretParams: GroupSecretParams, authCredential: AuthCredential) throws -> AuthCredentialPresentation {
    return try createAuthCredentialPresentation(randomness: Randomness.generate(), groupSecretParams: groupSecretParams, authCredential: authCredential)
  }

  public func createAuthCredentialPresentation(randomness: Randomness, groupSecretParams: GroupSecretParams, authCredential: AuthCredential) throws -> AuthCredentialPresentation {
    return try serverPublicParams.withUnsafePointerToSerialized { contents in
      try randomness.withUnsafePointerToBytes { randomness in
        try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
          try authCredential.withUnsafePointerToSerialized { authCredential in
            try invokeFnReturningSerialized {
              signal_server_public_params_create_auth_credential_presentation_deterministic($0, contents, randomness, groupSecretParams, authCredential)
            }
          }
        }
      }
    }
  }

}
