//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SenderKeyDistributionMessage: NativeHandleOwner<SignalMutPointerSenderKeyDistributionMessage> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerSenderKeyDistributionMessage>) -> SignalFfiErrorRef? {
        return signal_sender_key_distribution_message_destroy(handle.pointer)
    }

    public convenience init(
        from sender: ProtocolAddress,
        distributionId: UUID,
        store: SenderKeyStore,
        context: StoreContext
    ) throws {
        var result = SignalMutPointerSenderKeyDistributionMessage()
        try sender.withNativeHandle { senderHandle in
            try withUnsafePointer(to: distributionId.uuid) { distributionId in
                try withSenderKeyStore(store, context) {
                    try checkError(signal_sender_key_distribution_message_create(
                        &result,
                        senderHandle.const(),
                        distributionId,
                        $0
                    ))
                }
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public convenience init(bytes: [UInt8]) throws {
        var result = SignalMutPointerSenderKeyDistributionMessage()
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_sender_key_distribution_message_deserialize(&result, $0))
        }
        self.init(owned: NonNull(result)!)
    }

    public var signatureKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_sender_key_distribution_message_get_signature_key($0, nativeHandle.const())
                }
            }
        }
    }

    public var distributionId: UUID {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningUuid {
                    signal_sender_key_distribution_message_get_distribution_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var chainId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_sender_key_distribution_message_get_chain_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var iteration: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_sender_key_distribution_message_get_iteration($0, nativeHandle.const())
                }
            }
        }
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_key_distribution_message_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var chainKey: [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_key_distribution_message_get_chain_key($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerSenderKeyDistributionMessage: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerSenderKeyDistributionMessage

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

extension SignalConstPointerSenderKeyDistributionMessage: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
