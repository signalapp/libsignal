//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ServerPublicParams: NativeHandleOwner<SignalMutPointerServerPublicParams> {
    public convenience init(contents: [UInt8]) throws {
        var handle = SignalMutPointerServerPublicParams()
        try contents.withUnsafeBorrowedBuffer {
            try checkError(signal_server_public_params_deserialize(&handle, $0))
        }
        self.init(owned: NonNull(handle)!)
    }

    required init(owned: NonNull<SignalMutPointerServerPublicParams>) {
        super.init(owned: owned)
    }

    public func verifySignature(message: [UInt8], notarySignature: NotarySignature) throws {
        try withNativeHandle { contents in
            try message.withUnsafeBorrowedBuffer { message in
                try notarySignature.withUnsafePointerToSerialized { notarySignature in
                    try checkError(signal_server_public_params_verify_signature(contents.const(), message, notarySignature))
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try withNativeHandle { handle in
                try invokeFnReturningArray {
                    signal_server_public_params_serialize($0, handle.const())
                }
            }
        }
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerServerPublicParams>) -> SignalFfiErrorRef? {
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
