//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerZkProfileOperations {

  let serverSecretParams: ServerSecretParams

  public init(serverSecretParams: ServerSecretParams) {
    self.serverSecretParams = serverSecretParams
  }

  public func issueProfileKeyCredential(profileKeyCredentialRequest: ProfileKeyCredentialRequest, uuid: UUID, profileKeyCommitment: ProfileKeyCommitment) throws -> ProfileKeyCredentialResponse {
    return try issueProfileKeyCredential(randomness: Randomness.generate(), profileKeyCredentialRequest: profileKeyCredentialRequest, uuid: uuid, profileKeyCommitment: profileKeyCommitment)
  }

  public func issueProfileKeyCredential(randomness: Randomness, profileKeyCredentialRequest: ProfileKeyCredentialRequest, uuid: UUID, profileKeyCommitment: ProfileKeyCommitment) throws -> ProfileKeyCredentialResponse {
    return try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try profileKeyCredentialRequest.withUnsafePointerToSerialized { request in
          try withUnsafePointer(to: uuid.uuid) { uuid in
            try profileKeyCommitment.withUnsafePointerToSerialized { commitment in
              try invokeFnReturningSerialized {
                signal_server_secret_params_issue_profile_key_credential_deterministic($0, serverSecretParams, randomness, request, uuid, commitment)
              }
            }
          }
        }
      }
    }
  }

  public func verifyProfileKeyCredentialPresentation(groupPublicParams: GroupPublicParams, profileKeyCredentialPresentation: ProfileKeyCredentialPresentation) throws {
    try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try groupPublicParams.withUnsafePointerToSerialized { groupPublicParams in
        try profileKeyCredentialPresentation.withUnsafePointerToSerialized { presentation in
          try checkError(signal_server_secret_params_verify_profile_key_credential_presentation(serverSecretParams, groupPublicParams, presentation))
        }
      }
    }
  }

}
