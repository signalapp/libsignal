//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SenderKeyDistributionMessage: NativeHandleOwner<SignalMutPointerSenderKeyDistributionMessage> {
    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerSenderKeyDistributionMessage>
    ) -> SignalFfiErrorRef? {
        return signal_sender_key_distribution_message_destroy(handle.pointer)
    }

    public convenience init(
        from sender: ProtocolAddress,
        distributionId: UUID,
        store: SenderKeyStore,
        context: StoreContext
    ) throws {
        let result = try sender.withNativeHandle { senderHandle in
            try withUnsafePointer(to: distributionId.uuid) { distributionId in
                try withSenderKeyStore(store, context) { store in
                    try invokeFnReturningValueByPointer(.init()) {
                        signal_sender_key_distribution_message_create(
                            $0,
                            senderHandle.const(),
                            distributionId,
                            store
                        )
                    }
                }
            }
        }
        self.init(owned: NonNull(result)!)
    }

    public convenience init(bytes: Data) throws {
        let result = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_sender_key_distribution_message_deserialize($0, bytes)
            }
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

    public func serialize() -> Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_sender_key_distribution_message_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var chainKey: Data {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
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
