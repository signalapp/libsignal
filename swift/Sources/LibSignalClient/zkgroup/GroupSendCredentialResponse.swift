//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class GroupSendCredentialResponse: ByteArray {
  public required init(contents: [UInt8]) throws {
    try super.init(contents, checkValid: signal_group_send_credential_response_check_valid_contents)
  }

  public static func defaultExpiration() -> Date {
    let expiration = failOnError {
      try invokeFnReturningInteger {
        signal_group_send_credential_response_default_expiration_based_on_current_time($0)
      }
    }
    return Date(timeIntervalSince1970: TimeInterval(expiration))
  }

  public static func issueCredential(groupMembers: [UuidCiphertext], requestingMember: UuidCiphertext, expiration: Date = GroupSendCredentialResponse.defaultExpiration(), params: ServerSecretParams) -> GroupSendCredentialResponse {
    return failOnError {
      issueCredential(groupMembers: groupMembers, requestingMember: requestingMember, expiration: expiration, params: params, randomness: try .generate())
    }
  }

  public static func issueCredential(groupMembers: [UuidCiphertext], requestingMember: UuidCiphertext, expiration: Date = GroupSendCredentialResponse.defaultExpiration(), params: ServerSecretParams, randomness: Randomness) -> GroupSendCredentialResponse {
    let concatenated = groupMembers.flatMap { $0.serialize() }

    return failOnError {
      return try concatenated.withUnsafeBorrowedBuffer { concatenated in
        try requestingMember.withUnsafePointerToSerialized { requestingMember in
          try params.withUnsafePointerToSerialized { params in
            try randomness.withUnsafePointerToBytes { randomness in
              try invokeFnReturningVariableLengthSerialized {
                signal_group_send_credential_response_issue_deterministic(
                  $0,
                  concatenated,
                  requestingMember,
                  UInt64(expiration.timeIntervalSince1970),
                  params,
                  randomness)
              }
            }
          }
        }
      }
    }
  }

  public func receive(groupMembers: [ServiceId], localUser: Aci, now: Date = Date(), serverParams: ServerPublicParams, groupParams: GroupSecretParams) throws -> GroupSendCredential {
    return try withUnsafeBorrowedBuffer { response in
      try ServiceId.concatenatedFixedWidthBinary(groupMembers).withUnsafeBorrowedBuffer { groupMembers in
        try localUser.withPointerToFixedWidthBinary { localUser in
          try serverParams.withUnsafePointerToSerialized { serverParams in
            try groupParams.withUnsafePointerToSerialized { groupParams in
              try invokeFnReturningVariableLengthSerialized {
                signal_group_send_credential_response_receive($0, response, groupMembers, localUser, UInt64(now.timeIntervalSince1970), serverParams, groupParams)
              }
            }
          }
        }
      }
    }
  }
}
