//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

///
/// Cds2Client provides bindings to interact with Signal's v2 Contact Discovery Service.
///
/// See ``SgxClient``
public class Cds2Client: SgxClient {
    public convenience init(
        mrenclave: some ContiguousBytes,
        attestationMessage: some ContiguousBytes,
        currentDate: Date
    ) throws {
        let handle: OpaquePointer? = try attestationMessage.withUnsafeBorrowedBuffer { attestationMessageBuffer in
            try mrenclave.withUnsafeBorrowedBuffer { mrenclaveBuffer in
                var result: OpaquePointer?
                try checkError(signal_cds2_client_state_new(
                    &result,
                    mrenclaveBuffer,
                    attestationMessageBuffer,
                    UInt64(currentDate.timeIntervalSince1970 * 1000)
                ))
                return result
            }
        }
        self.init(owned: handle!)
    }
}
