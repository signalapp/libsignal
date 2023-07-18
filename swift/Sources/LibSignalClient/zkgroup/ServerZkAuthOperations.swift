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

  public func issueAuthCredential(aci: Aci, redemptionTime: UInt32) throws -> AuthCredentialResponse {
    return try issueAuthCredential(randomness: Randomness.generate(), aci: aci, redemptionTime: redemptionTime)
  }

  public func issueAuthCredential(randomness: Randomness, aci: Aci, redemptionTime: UInt32) throws -> AuthCredentialResponse {
    return try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try aci.withPointerToFixedWidthBinary { aci in
          try invokeFnReturningSerialized {
            signal_server_secret_params_issue_auth_credential_deterministic($0, serverSecretParams, randomness, aci, redemptionTime)
          }
        }
      }
    }
  }

  public func issueAuthCredentialWithPniAsServiceId(aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
    return try issueAuthCredentialWithPniAsServiceId(randomness: Randomness.generate(), aci: aci, pni: pni, redemptionTime: redemptionTime)
  }

  public func issueAuthCredentialWithPniAsServiceId(randomness: Randomness, aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
    return try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try aci.withPointerToFixedWidthBinary { aci in
          try pni.withPointerToFixedWidthBinary { pni in
            try invokeFnReturningSerialized {
              signal_server_secret_params_issue_auth_credential_with_pni_as_service_id_deterministic($0, serverSecretParams, randomness, aci, pni, redemptionTime)
            }
          }
        }
      }
    }
  }

  public func issueAuthCredentialWithPniAsAci(aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
    return try issueAuthCredentialWithPniAsAci(randomness: Randomness.generate(), aci: aci, pni: pni, redemptionTime: redemptionTime)
  }

  public func issueAuthCredentialWithPniAsAci(randomness: Randomness, aci: Aci, pni: Pni, redemptionTime: UInt64) throws -> AuthCredentialWithPniResponse {
    return try serverSecretParams.withUnsafePointerToSerialized { serverSecretParams in
      try randomness.withUnsafePointerToBytes { randomness in
        try aci.withPointerToFixedWidthBinary { aci in
          try pni.withPointerToFixedWidthBinary { pni in
            try invokeFnReturningSerialized {
              signal_server_secret_params_issue_auth_credential_with_pni_as_aci_deterministic($0, serverSecretParams, randomness, aci, pni, redemptionTime)
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
