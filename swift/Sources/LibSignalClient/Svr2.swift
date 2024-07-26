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
    public convenience init(
        mrenclave: some ContiguousBytes,
        attestationMessage: some ContiguousBytes,
        currentDate: Date
    ) throws {
        let handle: OpaquePointer? = try attestationMessage.withUnsafeBorrowedBuffer { attestationMessageBuffer in
            try mrenclave.withUnsafeBorrowedBuffer { mrenclaveBuffer in
                var result: OpaquePointer?
                try checkError(signal_svr2_client_new(
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
