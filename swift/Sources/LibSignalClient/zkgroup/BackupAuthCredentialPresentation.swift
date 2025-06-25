//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class BackupAuthCredentialPresentation: ByteArray, @unchecked Sendable {
    public required init(contents: Data) throws {
        try super.init(contents, checkValid: signal_backup_auth_credential_presentation_check_valid_contents)
    }

    public func verify(now: Date = Date(), serverParams: GenericServerSecretParams) throws {
        try withAllBorrowed(self, serverParams) { contents, serverParams in
            try checkError(
                signal_backup_auth_credential_presentation_verify(
                    contents,
                    UInt64(now.timeIntervalSince1970),
                    serverParams
                )
            )
        }
    }
}
