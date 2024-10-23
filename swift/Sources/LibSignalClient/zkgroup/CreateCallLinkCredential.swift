//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class CreateCallLinkCredential: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_create_call_link_credential_check_valid_contents)
    }

    public func present<RoomId: ContiguousBytes>(roomId: RoomId, userId: Aci, serverParams: GenericServerPublicParams, callLinkParams: CallLinkSecretParams) -> CreateCallLinkCredentialPresentation {
        return failOnError {
            self.present(roomId: roomId, userId: userId, serverParams: serverParams, callLinkParams: callLinkParams, randomness: try .generate())
        }
    }

    public func present<RoomId: ContiguousBytes>(roomId: RoomId, userId: Aci, serverParams: GenericServerPublicParams, callLinkParams: CallLinkSecretParams, randomness: Randomness) -> CreateCallLinkCredentialPresentation {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try roomId.withUnsafeBorrowedBuffer { roomId in
                    try userId.withPointerToFixedWidthBinary { userId in
                        try serverParams.withUnsafeBorrowedBuffer { serverParams in
                            try callLinkParams.withUnsafeBorrowedBuffer { callLinkParams in
                                try randomness.withUnsafePointerToBytes { randomness in
                                    try invokeFnReturningVariableLengthSerialized {
                                        signal_create_call_link_credential_present_deterministic($0, contents, roomId, userId, serverParams, callLinkParams, randomness)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
