//
// Copyright 2020-2022 Signal Messenger, LLC.
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

  @available(*, deprecated, message: "superseded by AuthCredentialWithPni + ProfileKeyCredential")
  public func createPniCredentialRequestContext(aci: UUID, pni: UUID, profileKey: ProfileKey) throws -> PniCredentialRequestContext {
    return try createPniCredentialRequestContext(randomness: Randomness.generate(), aci: aci, pni: pni, profileKey: profileKey)
  }

  @available(*, deprecated, message: "superseded by AuthCredentialWithPni + ProfileKeyCredential")
  public func createPniCredentialRequestContext(randomness: Randomness, aci: UUID, pni: UUID, profileKey: ProfileKey) throws -> PniCredentialRequestContext {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try withUnsafePointer(to: aci.uuid) { aci in
          try withUnsafePointer(to: pni.uuid) { pni in
            try profileKey.withUnsafePointerToSerialized { profileKey in
              try invokeFnReturningSerialized {
                signal_server_public_params_create_pni_credential_request_context_deterministic($0, serverPublicParams, randomness, aci, pni, profileKey)
              }
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

  public func receiveExpiringProfileKeyCredential(
    profileKeyCredentialRequestContext: ProfileKeyCredentialRequestContext,
    profileKeyCredentialResponse: ExpiringProfileKeyCredentialResponse,
    now: Date = Date()
  ) throws -> ExpiringProfileKeyCredential {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try profileKeyCredentialRequestContext.withUnsafePointerToSerialized { requestContext in
        try profileKeyCredentialResponse.withUnsafePointerToSerialized { response in
          try invokeFnReturningSerialized {
            signal_server_public_params_receive_expiring_profile_key_credential($0, serverPublicParams, requestContext, response, UInt64(now.timeIntervalSince1970))
          }
        }
      }
    }
  }

  @available(*, deprecated, message: "superseded by AuthCredentialWithPni + ProfileKeyCredential")
  public func receivePniCredential(requestContext: PniCredentialRequestContext, response: PniCredentialResponse) throws -> PniCredential {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try requestContext.withUnsafePointerToSerialized { requestContext in
        try response.withUnsafePointerToSerialized { response in
          try invokeFnReturningSerialized {
            signal_server_public_params_receive_pni_credential($0, serverPublicParams, requestContext, response)
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
            try invokeFnReturningVariableLengthSerialized {
              signal_server_public_params_create_profile_key_credential_presentation_deterministic($0, $1, serverPublicParams, randomness, groupSecretParams, profileKeyCredential)
            }
          }
        }
      }
    }
  }

  public func createProfileKeyCredentialPresentation(groupSecretParams: GroupSecretParams, profileKeyCredential: ExpiringProfileKeyCredential) throws -> ProfileKeyCredentialPresentation {
    return try createProfileKeyCredentialPresentation(randomness: Randomness.generate(), groupSecretParams: groupSecretParams, profileKeyCredential: profileKeyCredential)
  }

  public func createProfileKeyCredentialPresentation(randomness: Randomness, groupSecretParams: GroupSecretParams, profileKeyCredential: ExpiringProfileKeyCredential) throws -> ProfileKeyCredentialPresentation {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
          try profileKeyCredential.withUnsafePointerToSerialized { profileKeyCredential in
            try invokeFnReturningVariableLengthSerialized {
              signal_server_public_params_create_expiring_profile_key_credential_presentation_deterministic($0, $1, serverPublicParams, randomness, groupSecretParams, profileKeyCredential)
            }
          }
        }
      }
    }
  }

  @available(*, deprecated, message: "superseded by AuthCredentialWithPni + ProfileKeyCredential")
  public func createPniCredentialPresentation(groupSecretParams: GroupSecretParams, credential: PniCredential) throws -> PniCredentialPresentation {
    return try createPniCredentialPresentation(randomness: Randomness.generate(), groupSecretParams: groupSecretParams, credential: credential)
  }

  @available(*, deprecated, message: "superseded by AuthCredentialWithPni + ProfileKeyCredential")
  public func createPniCredentialPresentation(randomness: Randomness, groupSecretParams: GroupSecretParams, credential: PniCredential) throws -> PniCredentialPresentation {
    return try serverPublicParams.withUnsafePointerToSerialized { serverPublicParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try groupSecretParams.withUnsafePointerToSerialized { groupSecretParams in
          try credential.withUnsafePointerToSerialized { credential in
            try invokeFnReturningVariableLengthSerialized {
              signal_server_public_params_create_pni_credential_presentation_deterministic($0, $1, serverPublicParams, randomness, groupSecretParams, credential)
            }
          }
        }
      }
    }
  }

}
