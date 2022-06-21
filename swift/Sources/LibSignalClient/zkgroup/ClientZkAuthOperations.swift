//
// Copyright 2020-2022 Signal Messenger, LLC.
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

  /// Produces the `AuthCredentialWithPni` from a server-generated `AuthCredentialWithPniResponse`.
  ///
  /// - parameter redemptionTime: This is provided by the server as an integer, and should be passed through directly.
  public func receiveAuthCredentialWithPni(aci: UUID, pni: UUID, redemptionTime: UInt64, authCredentialResponse: AuthCredentialWithPniResponse) throws -> AuthCredentialWithPni {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try withUnsafePointer(to: aci.uuid) { aci in
        try withUnsafePointer(to: pni.uuid) { pni in
          try authCredentialResponse.withUnsafePointerToSerialized { authCredentialResponse in
            try invokeFnReturningSerialized {
              signal_server_public_params_receive_auth_credential_with_pni($0, serverPublicParams, aci, pni, redemptionTime, authCredentialResponse)
            }
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
            try invokeFnReturningVariableLengthSerialized {
              signal_server_public_params_create_auth_credential_presentation_deterministic($0, $1, contents, randomness, groupSecretParams, authCredential)
            }
          }
        }
      }
    }
  }

  public func createAuthCredentialPresentation(groupSecretParams: GroupSecretParams, authCredential: AuthCredentialWithPni) throws -> AuthCredentialPresentation {
    return try createAuthCredentialPresentation(randomness: Randomness.generate(), groupSecretParams: groupSecretParams, authCredential: authCredential)
  }

  public func createAuthCredentialPresentation(randomness: Randomness, groupSecretParams: GroupSecretParams, authCredential: AuthCredentialWithPni) throws -> AuthCredentialPresentation {
    return try serverPublicParams.withUnsafePointerToSerialized { contents in
      try randomness.withUnsafePointerToBytes { randomness in
        try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
          try authCredential.withUnsafePointerToSerialized { authCredential in
            try invokeFnReturningVariableLengthSerialized {
              signal_server_public_params_create_auth_credential_with_pni_presentation_deterministic($0, $1, contents, randomness, groupSecretParams, authCredential)
            }
          }
        }
      }
    }
  }

}
