//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// The key pair used to issue and verify group send endorsements.
///
/// Group send endorsements use a different key pair depending on the endorsement's expiration (but
/// not the user ID being endorsed). The server may cache these keys to avoid the (small) cost of
/// deriving them from the root key in ``ServerSecretParams``. The key object stores the expiration
/// so that it doesn't need to be provided again when issuing endorsements.
///
/// - SeeAlso: ``GroupSendEndorsementsResponse/issue(groupMembers:keyPair:)``,
///   ``GroupSendFullToken/verify(userIds:now:keyPair:)``
public class GroupSendDerivedKeyPair: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_group_send_derived_key_pair_check_valid_contents)
    }

    /// Derives a new key for group send endorsements that expire at `expiration`.
    ///
    /// `expiration` must be day-aligned as a protection against fingerprinting by the issuing
    /// server.
    public static func forExpiration(_ expiration: Date, params: ServerSecretParams) -> GroupSendDerivedKeyPair {
        return failOnError {
            try params.withNativeHandle { params in
                try invokeFnReturningVariableLengthSerialized {
                    signal_group_send_derived_key_pair_for_expiration($0, UInt64(expiration.timeIntervalSince1970), params)
                }
            }
        }
    }
}
