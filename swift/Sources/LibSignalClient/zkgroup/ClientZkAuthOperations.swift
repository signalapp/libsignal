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

  public func receiveAuthCredential(aci: Aci, redemptionTime: UInt32, authCredentialResponse: AuthCredentialResponse) throws -> AuthCredential {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try aci.withPointerToFixedWidthBinary { uuid in
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
  public func receiveAuthCredentialWithPniAsServiceId(aci: Aci, pni: Pni, redemptionTime: UInt64, authCredentialResponse: AuthCredentialWithPniResponse) throws -> AuthCredentialWithPni {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try aci.withPointerToFixedWidthBinary { aci in
        try pni.withPointerToFixedWidthBinary { pni in
          try authCredentialResponse.withUnsafePointerToSerialized { authCredentialResponse in
            try invokeFnReturningSerialized {
              signal_server_public_params_receive_auth_credential_with_pni_as_service_id($0, serverPublicParams, aci, pni, redemptionTime, authCredentialResponse)
            }
          }
        }
      }
    }
  }

  /// Produces the `AuthCredentialWithPni` from a server-generated `AuthCredentialWithPniResponse`.
  ///
  /// This older style of AuthCredentialWithPni will not actually have a usable PNI field,
  /// but can still be used for authenticating with an ACI.
  ///
  /// - parameter redemptionTime: This is provided by the server as an integer, and should be passed through directly.
  public func receiveAuthCredentialWithPniAsAci(aci: Aci, pni: Pni, redemptionTime: UInt64, authCredentialResponse: AuthCredentialWithPniResponse) throws -> AuthCredentialWithPni {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try aci.withPointerToFixedWidthBinary { aci in
        try pni.withPointerToFixedWidthBinary { pni in
          try authCredentialResponse.withUnsafePointerToSerialized { authCredentialResponse in
            try invokeFnReturningSerialized {
              signal_server_public_params_receive_auth_credential_with_pni_as_aci($0, serverPublicParams, aci, pni, redemptionTime, authCredentialResponse)
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
              signal_server_public_params_create_auth_credential_presentation_deterministic($0, contents, randomness, groupSecretParams, authCredential)
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
              signal_server_public_params_create_auth_credential_with_pni_presentation_deterministic($0, contents, randomness, groupSecretParams, authCredential)
            }
          }
        }
      }
    }
  }

}
