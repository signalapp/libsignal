//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerPublicParams: NativeHandleOwner<SignalMutPointerServerPublicParams> {
    public convenience init(contents: Data) throws {
        let handle = try contents.withUnsafeBorrowedBuffer { contents in
            try invokeFnReturningValueByPointer(.init()) {
                signal_server_public_params_deserialize($0, contents)
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    required init(owned: NonNull<SignalMutPointerServerPublicParams>) {
        super.init(owned: owned)
    }

    /**
     * Get the serialized form of the params' endorsement key.
     *
     * Allows decoupling RingRTC's use of endorsements from libsignal's.
     */
    public var endorsementPublicKey: Data {
        return failOnError {
            try self.withNativeHandle { handle in
                try invokeFnReturningData {
                    signal_server_public_params_get_endorsement_public_key($0, handle.const())
                }
            }
        }
    }

    public func verifySignature(message: Data, notarySignature: NotarySignature) throws {
        try withNativeHandle { contents in
            try message.withUnsafeBorrowedBuffer { message in
                try notarySignature.withUnsafePointerToSerialized { notarySignature in
                    try checkError(
                        signal_server_public_params_verify_signature(contents.const(), message, notarySignature)
                    )
                }
            }
        }
    }

    public func serialize() -> Data {
        return failOnError {
            try withNativeHandle { handle in
                try invokeFnReturningData {
                    signal_server_public_params_serialize($0, handle.const())
                }
            }
        }
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerServerPublicParams>
    ) -> SignalFfiErrorRef? {
        signal_server_public_params_destroy(handle.pointer)
    }
}

extension SignalMutPointerServerPublicParams: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerServerPublicParams

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerServerPublicParams: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
