//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

///
/// Svr2Client provides bindings to interact with Signal's v2 Secure Value Recovery service.
///
/// See ``SgxClient``
public class Svr2Client: SgxClient {

    private var groupId: UInt64

    /// Hash a pin so it can be used with SVR2.
    ///
    /// - parameter pin: An already normalized UTF-8 encoded byte representation of the pin
    /// - parameter username: The Basic Auth username used to authenticate with SVR2
    /// - returns: A `PinHash`
    public func hashPin<PinBytes: ContiguousBytes, UsernameBytes: ContiguousBytes>(_ pin: PinBytes, forUser username: UsernameBytes) throws -> PinHash {
        try PinHash(pin: pin, username: username, groupId: self.groupId)
    }

    public static func create_NOT_FOR_PRODUCTION<MrenclaveBytes, AttestationBytes>(mrenclave: MrenclaveBytes, attestationMessage: AttestationBytes, currentDate: Date) throws -> Svr2Client
    where MrenclaveBytes: ContiguousBytes, AttestationBytes: ContiguousBytes {
        return try Svr2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
    }

    private convenience init<MrenclaveBytes, AttestationBytes>(mrenclave: MrenclaveBytes, attestationMessage: AttestationBytes, currentDate: Date) throws
    where MrenclaveBytes: ContiguousBytes, AttestationBytes: ContiguousBytes {
        var svr2Client: OpaquePointer?
        try attestationMessage.withUnsafeBorrowedBuffer { attestationMessageBuffer in
            try mrenclave.withUnsafeBorrowedBuffer { mrenclaveBuffer in
                try checkError(
                    signal_svr2_client_new(
                        &svr2Client,
                        mrenclaveBuffer,
                        attestationMessageBuffer,
                        UInt64(currentDate.timeIntervalSince1970 * 1000)))

            }
        }
        defer { failOnError(signal_svr2_client_destroy(svr2Client!)) }

        let groupId = failOnError {
            try invokeFnReturningInteger {
                signal_svr2_client_group_id($0, svr2Client)
            }
        }

        var sgxClient: OpaquePointer?
        failOnError {
            try checkError(signal_svr2_client_take_sgx_client_state(&sgxClient, svr2Client))
        }

        self.init(owned: sgxClient!, groupId: groupId)
    }

    internal required init(owned handle: OpaquePointer) {
        self.groupId = 0
        super.init(owned: handle)
    }

    private init(owned handle: OpaquePointer, groupId: UInt64) {
        self.groupId = groupId
        super.init(owned: handle)
    }
}
