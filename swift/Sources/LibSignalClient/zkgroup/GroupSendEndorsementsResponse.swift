//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// A set of endorsements of the members in a group, along with a proof of their validity.
///
/// Issued by the group server based on the group's member ciphertexts. The endorsements will
/// eventually be verified by the chat server in the form of ``GroupSendFullToken``s. See
/// ``GroupSendEndorsement`` for a full description of the endorsement flow from the client's
/// perspective.
public class GroupSendEndorsementsResponse: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_group_send_endorsements_response_check_valid_contents)
    }

    /// Issues a new set of endorsements for `groupMembers`.
    public static func issue(
        groupMembers: [UuidCiphertext],
        keyPair: GroupSendDerivedKeyPair
    ) -> GroupSendEndorsementsResponse {
        return failOnError {
            self.issue(groupMembers: groupMembers, keyPair: keyPair, randomness: try .generate())
        }
    }

    /// Issues a new set of endorsements for `groupMembers`, with an explictly-chosen source of
    /// randomness.
    ///
    /// Should only be used for testing purposes.
    ///
    /// - SeeAlso: ``issue(groupMembers:keyPair:)``
    public static func issue(
        groupMembers: [UuidCiphertext],
        keyPair: GroupSendDerivedKeyPair,
        randomness: Randomness
    ) -> GroupSendEndorsementsResponse {
        let concatenated = groupMembers.flatMap { $0.serialize() }

        return failOnError {
            try concatenated.withUnsafeBorrowedBuffer { concatenated in
                try keyPair.withUnsafeBorrowedBuffer { keyPair in
                    try randomness.withUnsafePointerToBytes { randomness in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_group_send_endorsements_response_issue_deterministic($0, concatenated, keyPair, randomness)
                        }
                    }
                }
            }
        }
    }

    /// The expiration for the contained endorsements.
    public var expiration: Date {
        let expirationSinceEpoch: UInt64 = failOnError {
            try withUnsafeBorrowedBuffer { response in
                try invokeFnReturningInteger {
                    signal_group_send_endorsements_response_get_expiration($0, response)
                }
            }
        }
        return Date(timeIntervalSince1970: TimeInterval(expirationSinceEpoch))
    }

    /// A collection of endorsements known to be valid.
    ///
    /// The result of the `receive` operations on ``GroupSendEndorsementsResponse``. Contains an
    /// endorsement for each member of the group, in the same order they were originally provided,
    /// plus a combined endorsement for "everyone but me", intended for multi-recipient sends.
    public struct ReceivedEndorsements: Sendable {
        public var endorsements: [GroupSendEndorsement]
        public var combinedEndorsement: GroupSendEndorsement
    }

    /// Receives, validates, and extracts the endorsements from a response.
    ///
    /// Note that the `receive` operation is provided for both ``ServiceId``s and
    /// ``UuidCiphertext``s. If you already have the ciphertexts for the group members available,
    /// ``receive(groupMembers:localUser:now:serverParams:)`` should be faster; if you don't, this
    /// method is faster than generating the ciphertexts and throwing them away afterwards.
    ///
    /// `localUser` should be included in `groupMembers`.
    ///
    /// - Throws: ``SignalError/verificationFailed(_:)`` if the endorsements are not valid for any
    ///   reason
    public func receive(
        groupMembers: some Collection<ServiceId>,
        localUser: Aci,
        now: Date = Date(),
        groupParams: GroupSecretParams,
        serverParams: ServerPublicParams
    ) throws -> ReceivedEndorsements {
        let rawEndorsements = try withUnsafeBorrowedBuffer { response in
            try ServiceId.concatenatedFixedWidthBinary(groupMembers).withUnsafeBorrowedBuffer { groupMembers in
                try localUser.withPointerToFixedWidthBinary { localUser in
                    try groupParams.withUnsafePointerToSerialized { groupParams in
                        try serverParams.withNativeHandle { serverParams in
                            try invokeFnReturningBytestringArray {
                                signal_group_send_endorsements_response_receive_and_combine_with_service_ids($0, response, groupMembers, localUser, UInt64(now.timeIntervalSince1970), groupParams, serverParams)
                            }
                        }
                    }
                }
            }
        }

        // Normally we don't notice the cost of validating just-created zkgroup objects,
        // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
        let endorsements = rawEndorsements.dropLast().map { GroupSendEndorsement(unchecked: $0) }
        let combinedEndorsement = GroupSendEndorsement(unchecked: rawEndorsements.last!)
        return ReceivedEndorsements(endorsements: endorsements, combinedEndorsement: combinedEndorsement)
    }

    /// Receives, validates, and extracts the endorsements from a response.
    ///
    /// Note that the `receive` operation is provided for both ``ServiceId``s and
    /// ``UuidCiphertext``s. If you already have the ciphertexts for the group members available,
    /// this method should be faster; if you don't,
    /// ``receive(groupMembers:localUser:now:groupParams:serverParams:)`` is faster than generating
    /// the ciphertexts and throwing them away afterwards.
    ///
    /// `localUser` should be included in `groupMembers`.
    ///
    /// - Throws: ``SignalError/verificationFailed(_:)`` if the endorsements are not valid for any
    ///   reason
    public func receive(
        groupMembers: some Sequence<UuidCiphertext>,
        localUser: UuidCiphertext,
        now: Date = Date(),
        serverParams: ServerPublicParams
    ) throws -> ReceivedEndorsements {
        let rawEndorsements = try withUnsafeBorrowedBuffer { response in
            try groupMembers.flatMap { $0.serialize() }.withUnsafeBorrowedBuffer { groupMembers in
                try localUser.withUnsafeBorrowedBuffer { localUser in
                    try serverParams.withNativeHandle { serverParams in
                        try invokeFnReturningBytestringArray {
                            signal_group_send_endorsements_response_receive_and_combine_with_ciphertexts($0, response, groupMembers, localUser, UInt64(now.timeIntervalSince1970), serverParams)
                        }
                    }
                }
            }
        }

        // Normally we don't notice the cost of validating just-created zkgroup objects,
        // but in this case we may have up to 1000 of these. Let's assume they're created correctly.
        let endorsements = rawEndorsements.dropLast().map { GroupSendEndorsement(unchecked: $0) }
        let combinedEndorsement = GroupSendEndorsement(unchecked: rawEndorsements.last!)
        return ReceivedEndorsements(endorsements: endorsements, combinedEndorsement: combinedEndorsement)
    }
}
