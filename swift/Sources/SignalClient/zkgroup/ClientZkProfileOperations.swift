//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ClientZkProfileOperations {

  let serverPublicParams: ServerPublicParams

  public init(serverPublicParams: ServerPublicParams) {
    self.serverPublicParams = serverPublicParams
  }

  public func createProfileKeyCredentialRequestContext(uuid: UUID, profileKey: ProfileKey) throws -> ProfileKeyCredentialRequestContext {
    return try createProfileKeyCredentialRequestContext(randomness: Randomness.generate(), uuid: uuid, profileKey: profileKey)
  }

  public func createProfileKeyCredentialRequestContext(randomness: Randomness, uuid: UUID, profileKey: ProfileKey) throws -> ProfileKeyCredentialRequestContext {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try withUnsafePointer(to: uuid.uuid) { uuid in
          try profileKey.withUnsafePointerToSerialized { profileKey in
            try invokeFnReturningSerialized {
              signal_server_public_params_create_profile_key_credential_request_context_deterministic($0, serverPublicParams, randomness, uuid, profileKey)
            }
          }
        }
      }
    }
  }

  public func receiveProfileKeyCredential(profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext, profileKeyCredentialResponse: ProfileKeyCredentialResponse) throws -> ProfileKeyCredential {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try profileKeyCredentialRequestContext.withUnsafePointerToSerialized { requestContext in
        try profileKeyCredentialResponse.withUnsafePointerToSerialized { response in
          try invokeFnReturningSerialized {
            signal_server_public_params_receive_profile_key_credential($0, serverPublicParams, requestContext, response)
          }
        }
      }
    }
  }

  public func createProfileKeyCredentialPresentation(groupSecretParams: GroupSecretParams, profileKeyCredential: ProfileKeyCredential) throws -> ProfileKeyCredentialPresentation {
    return try createProfileKeyCredentialPresentation(randomness: Randomness.generate(), groupSecretParams: groupSecretParams, profileKeyCredential: profileKeyCredential)
  }

  public func createProfileKeyCredentialPresentation(randomness: Randomness, groupSecretParams: GroupSecretParams, profileKeyCredential: ProfileKeyCredential) throws -> ProfileKeyCredentialPresentation {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
          try profileKeyCredential.withUnsafePointerToSerialized { profileKeyCredential in
            try invokeFnReturningSerialized {
              signal_server_public_params_create_profile_key_credential_presentation_deterministic($0, serverPublicParams, randomness, groupSecretParams, profileKeyCredential)
            }
          }
        }
      }
    }
  }

}
