//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// An endorsement for a user or set of users in a group.
///
/// GroupSendEndorsements provide a form of authorization by demonstrating that the holder of the
/// endorsement is in a group with a particular user or set of users. They can be
/// [combined](doc:GroupSendEndorsement/combine(_:)) and
/// [removed](doc:GroupSendEndorsement/byRemoving(_:)) in a set-like fashion.
///
/// The endorsement "flow" starts with receiving a ``GroupSendEndorsementsResponse`` from the group
/// server, which contains endorsements for all members in a group (including the local user). The
/// response object provides the single expiration for all the endorsements. From there, the
/// `receive` method produces a ``GroupSendEndorsementsResponse/ReceivedEndorsements``, which
/// exposes the individual endorsements as well as a combined endorsement for everyone but the local
/// user. Clients should save these endorsements and the expiration with the group state.
///
/// When it comes time to send a message to an individual user, clients should check to see if they
/// have a ``GroupSendEndorsement/Token`` for that user, and generate and cache one using
/// ``GroupSendEndorsement/toToken(groupParams:)`` if not. The token should then be converted to a
/// full token using ``GroupSendEndorsement/Token/toFullToken(expiration:)``, providing the
/// expiration saved previously. Finally, the serialized full token can be used as authorization in
/// a request to the chat server.
///
/// Similarly, when it comes time to send a message to the group, clients should start by
/// [removing](doc:GroupSendEndorsement/byRemoving(_:)) the endorsements of any users they are
/// excluding (say, because they need a Sender Key Distribution Message first), and then converting
/// the resulting endorsement to a token. From there, the token can be converted to a full token and
/// serialized as for an individual send. (Saving the repeated work of converting to a token is left
/// to the clients here; worst case, it's still cheaper than a usual zkgroup presentation.)
public class GroupSendEndorsement: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_group_send_endorsement_check_valid_contents)
    }

    init(unchecked contents: [UInt8]) {
        try! super.init(contents, checkValid: { _ in nil })
    }

    /// Combines several endorsements into one.
    ///
    /// For example, if you have endorsements to send to Meredith and Aruna individually, then you
    /// can combine them to produce an endorsement to send a multi-recipient message to the two of
    /// them.
    public static func combine(_ endorsements: some Collection<GroupSendEndorsement>) -> GroupSendEndorsement {
        // Swift doesn't let us access an arbitrary number of arrays as pointers, so instead we
        // concatenate all the endorsements into one big buffer and then chop that up into borrowed
        // slices.
        var concatenated: [UInt8] = []
        var lengths: [Int] = []
        lengths.reserveCapacity(endorsements.count)
        for next in endorsements {
            let serializedNext = next.serialize()
            concatenated.append(contentsOf: serializedNext)
            lengths.append(serializedNext.count)
        }
        return concatenated.withUnsafeBytes { concatenated in
            var slices: [SignalBorrowedBuffer] = []
            slices.reserveCapacity(endorsements.count)
            var offset = 0
            for length in lengths {
                let slice = UnsafeRawBufferPointer(rebasing: concatenated[offset...].prefix(length))
                slices.append(SignalBorrowedBuffer(slice))
                offset += length
            }

            return slices.withUnsafeBufferPointer { slices in
                failOnError {
                    try invokeFnReturningVariableLengthSerialized {
                        signal_group_send_endorsement_combine($0, SignalBorrowedSliceOfBuffers(base: slices.baseAddress, length: slices.count))
                    }
                }
            }
        }
    }

    /// Removes an endorsement (individual or combined) from this combined endorsement.
    ///
    /// If `self` is *not* a combined endorsement, or `toRemove` includes endorsements that were not
    /// combined into `self`, the result will not generate valid tokens.
    public func byRemoving(_ toRemove: GroupSendEndorsement) -> GroupSendEndorsement {
        return failOnError {
            try withUnsafeBorrowedBuffer { endorsement in
                try toRemove.withUnsafeBorrowedBuffer { toRemove in
                    try invokeFnReturningVariableLengthSerialized {
                        signal_group_send_endorsement_remove($0, endorsement, toRemove)
                    }
                }
            }
        }
    }

    /// A minimal cacheable representation of an endorsement.
    ///
    /// This contains the minimal information needed to represent this specific endorsement; it must
    /// be converted to a ``GroupSendFullToken`` before sending to the chat server. (It is valid to
    /// do this immediately; it just uses up extra space.)
    ///
    /// Generated by ``GroupSendEndorsement/toToken(groupParams:)``.
    ///
    public class Token: ByteArray, @unchecked Sendable {
        public required init(contents: [UInt8]) throws {
            try super.init(contents, checkValid: signal_group_send_token_check_valid_contents)
        }

        /// Converts this token to a "full token", which can be sent to the chat server as
        /// authentication.
        ///
        /// `expiration` must be the same expiration that was in the original
        /// ``GroupSendEndorsementsResponse``, or the resulting token will fail to verify.
        public func toFullToken(expiration: Date) -> GroupSendFullToken {
            return failOnError {
                try withUnsafeBorrowedBuffer { token in
                    try invokeFnReturningVariableLengthSerialized {
                        signal_group_send_token_to_full_token($0, token, UInt64(expiration.timeIntervalSince1970))
                    }
                }
            }
        }
    }

    /// Generates a cacheable token used to authenticate sends.
    ///
    /// The token is no longer associated with the group; it merely identifies the user or set of
    /// users referenced by this endorsement. (Of course, a set of users is a pretty good stand-in
    /// for a group.)
    ///
    /// - SeeAlso: ``Token``
    public func toToken(groupParams: GroupSecretParams) -> Token {
        return failOnError {
            try withUnsafeBorrowedBuffer { endorsement in
                try groupParams.withUnsafePointerToSerialized { groupParams in
                    try invokeFnReturningVariableLengthSerialized {
                        signal_group_send_endorsement_to_token($0, endorsement, groupParams)
                    }
                }
            }
        }
    }

    /// Generates a token used to authenticate sends, ready to put in an auth header.
    ///
    /// `expiration` must be the same expiration that was in the original
    /// ``GroupSendEndorsementsResponse``, or the resulting token will fail to verify.
    ///
    /// Equivalent to ``toToken(groupParams:)`` followed by ``Token/toFullToken(expiration:)``.
    public func toFullToken(groupParams: GroupSecretParams, expiration: Date) -> GroupSendFullToken {
        return self.toToken(groupParams: groupParams).toFullToken(expiration: expiration)
    }
}
