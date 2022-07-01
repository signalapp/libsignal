//
// Copyright 2020-2022 Signal Messenger, LLC.
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

  public func issueAuthCredentialWithPni(aci: UUID, pni: UUID, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
    return try issueAuthCredentialWithPni(randomness: Randomness.generate(), aci: aci, pni: pni, redemptionTime: redemptionTime)
  }

  public func issueAuthCredentialWithPni(randomness: Randomness, aci: UUID, pni: UUID, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
    return try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try withUnsafePointer(to: aci.uuid) { aci in
          try withUnsafePointer(to: pni.uuid) { pni in
            try invokeFnReturningSerialized {
              signal_server_secret_params_issue_auth_credential_with_pni_deterministic($0, serverSecretParams, randomness, aci, pni, redemptionTime)
            }
          }
        }
      }
    }
  }

  public func verifyAuthCredentialPresentation(groupPublicParams: GroupPublicParams, authCredentialPresentation: AuthCredentialPresentation, now: Date = Date()) throws {
    try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try groupPublicParams.withUnsafePointerToSerialized { groupPublicParams in
        try authCredentialPresentation.withUnsafeBorrowedBuffer { authCredentialPresentation in
          try checkError(signal_server_secret_params_verify_auth_credential_presentation(serverSecretParams, groupPublicParams, authCredentialPresentation, UInt64(now.timeIntervalSince1970)))
        }
      }
    }
  }

}
