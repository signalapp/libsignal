//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// A long-term Ristretto ZK credential key pair owned by an account.
///
/// Distinct from the account's curve25519 identity key. Used as a binding identity across ZK
/// credentials issued to the account (currently the avatar upload credential).
///
/// The secret half must be persisted by the account holder and synced to linked devices. The
/// public half is uploaded to the server.
public class ZkCredentialKeyPair: ByteArray {
    public static func generate() -> ZkCredentialKeyPair {
        return failOnError {
            self.generate(randomness: try Randomness.generate())
        }
    }

    public static func generate(randomness: Randomness) -> ZkCredentialKeyPair {
        return failOnError {
            try randomness.withUnsafePointerToBytes { randomness in
                try invokeFnReturningVariableLengthSerialized {
                    signal_zk_credential_key_pair_generate_deterministic($0, randomness)
                }
            }
        }
    }

    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_zk_credential_key_pair_check_valid_contents)
    }

    public var publicKey: ZkCredentialPublicKey {
        failOnError {
            try withUnsafeBorrowedBuffer { keyPairBytes in
                try invokeFnReturningVariableLengthSerialized {
                    signal_zk_credential_key_pair_get_public_key($0, keyPairBytes)
                }
            }
        }
    }
}

/// The public half of a ``ZkCredentialKeyPair``.
public class ZkCredentialPublicKey: ByteArray {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_zk_credential_public_key_check_valid_contents)
    }

}
