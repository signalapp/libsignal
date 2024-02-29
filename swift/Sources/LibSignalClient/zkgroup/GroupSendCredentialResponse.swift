//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/**
 * The issuance of a credential indicating membership in a group, based on the set of *other* users
 * in the group with you.
 *
 * Follows the usual zkgroup pattern of "issue response -> receive response -> present credential ->
 * verify presentation".
 *
 * - SeeAlso: ``GroupSendCredential``, ``GroupSendCredentialPresentation``
 */
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

  /**
   * Issues a new credential stating that `requestingMember` is a member of a group containing
   * `groupMembers`.
   *
   * `groupMembers` should include `requestingMember` as well.
   */
  public static func issueCredential(groupMembers: [UuidCiphertext], requestingMember: UuidCiphertext, expiration: Date = GroupSendCredentialResponse.defaultExpiration(), params: ServerSecretParams) -> GroupSendCredentialResponse {
    return failOnError {
      issueCredential(groupMembers: groupMembers, requestingMember: requestingMember, expiration: expiration, params: params, randomness: try .generate())
    }
  }

  /**
   * Issues a new credential stating that `requestingMember` is a member of a group containing
   * `groupMembers`, with an explictly-chosen source of randomness.
   *
   * Should only be used for testing purposes.
   *
   * - SeeAlso: ``issueCredential(groupMembers:requestingMember:expiration:params:)``
   */
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

  /**
   * Receives, validates, and extracts the credential from a response.
   *
   * Note that the `receive` operation is provided for both ``ServiceId``s and ``UuidCiphertext``s.
   * If you already have the ciphertexts for the group members available,
   * ``receive(groupMembers:localUser:now:serverParams:groupParams:)-5ipwi`` will be *significantly*
   * faster; if you don't, this method is faster than generating the ciphertexts and throwing them
   * away afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * - Throws: ``SignalError/verificationFailed(_:)`` if the credential is not valid for any reason
   */
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

  /**
   * Receives, validates, and extracts the credential from a response.
   *
   * Note that the `receive` operation is provided for both ``ServiceId``s and ``UuidCiphertext``s.
   * If you already have the ciphertexts for the group members available, this method will be
   * *significantly* faster; if you don't,
   * ``receive(groupMembers:localUser:now:serverParams:groupParams:)-4eco5`` is faster than
   * generating the ciphertexts and
   * throwing them away afterwards.
   *
   * `localUser` should be included in `groupMembers`.
   *
   * - Throws: ``SignalError/verificationFailed(_:)`` if the credential is not valid for any reason
   */
  public func receive(groupMembers: [UuidCiphertext], localUser: UuidCiphertext, now: Date = Date(), serverParams: ServerPublicParams, groupParams: GroupSecretParams) throws -> GroupSendCredential {
    return try withUnsafeBorrowedBuffer { response in
      try groupMembers.flatMap { $0.serialize() }.withUnsafeBorrowedBuffer { groupMembers in
        try localUser.withUnsafePointerToSerialized { localUser in
          try serverParams.withUnsafePointerToSerialized { serverParams in
            try groupParams.withUnsafePointerToSerialized { groupParams in
              try invokeFnReturningVariableLengthSerialized {
                signal_group_send_credential_response_receive_with_ciphertexts($0, response, groupMembers, localUser, UInt64(now.timeIntervalSince1970), serverParams, groupParams)
              }
            }
          }
        }
      }
    }
  }
}
