//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class CreateCallLinkCredentialRequestContext: ByteArray, @unchecked Sendable {
    public required init(contents: [UInt8]) throws {
        try super.init(contents, checkValid: signal_create_call_link_credential_request_context_check_valid_contents)
    }

    public static func forRoomId<RoomId: ContiguousBytes>(_ roomId: RoomId) -> Self {
        return failOnError {
            self.forRoomId(roomId, randomness: try .generate())
        }
    }

    public static func forRoomId<RoomId: ContiguousBytes>(_ roomId: RoomId, randomness: Randomness) -> Self {
        return failOnError {
            try roomId.withUnsafeBorrowedBuffer { roomId in
                try randomness.withUnsafePointerToBytes { randomness in
                    try invokeFnReturningVariableLengthSerialized {
                        signal_create_call_link_credential_request_context_new_deterministic($0, roomId, randomness)
                    }
                }
            }
        }
    }

    public func getRequest() -> CreateCallLinkCredentialRequest {
        return failOnError {
            try withUnsafeBorrowedBuffer { contents in
                try invokeFnReturningVariableLengthSerialized {
                    signal_create_call_link_credential_request_context_get_request($0, contents)
                }
            }
        }
    }

    public func receive(_ response: CreateCallLinkCredentialResponse, userId: Aci, params: GenericServerPublicParams) throws -> CreateCallLinkCredential {
        return try withUnsafeBorrowedBuffer { contents in
            try response.withUnsafeBorrowedBuffer { response in
                try userId.withPointerToFixedWidthBinary { userId in
                    try params.withUnsafeBorrowedBuffer { params in
                        try invokeFnReturningVariableLengthSerialized {
                            signal_create_call_link_credential_request_context_receive_response($0, contents, response, userId, params)
                        }
                    }
                }
            }
        }
    }
}
