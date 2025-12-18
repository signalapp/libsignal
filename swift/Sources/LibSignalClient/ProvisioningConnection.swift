//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol ProvisioningConnectionListener: ConnectionEventsListener<ProvisioningConnection> {
    /// Called at the start of the provisioning process.
    ///
    /// `address` should be considered an opaque token to pass to the primary device (usually via QR
    /// code).
    ///
    /// `sendAck` can be called immediately to indicate successful delivery of the address.
    func provisioningConnection(
        _ connection: ProvisioningConnection,
        didReceiveAddress address: String,
        sendAck: @escaping () throws -> Void
    )

    /// Called once when the primary sends an "envelope" via the server (using the address from
    /// ``provisioningConnection(_:didReceiveAddress:sendAck:)``).
    ///
    /// Once the server receives the ack for this message (from `sendAck`), it will close this connection.
    func provisioningConnection(
        _ connection: ProvisioningConnection,
        didReceiveEnvelope envelope: Data,
        sendAck: @escaping () throws -> Void
    )
}

/// A chat connection used specifically for provisioning linked devices.
///
/// An instance of this object is obtained via call to ``Net/connectProvisioning()``.
/// Before an obtained instance can be used, it must be started by calling ``ProvisioningConnection/start(listener:)``.
/// Note that no messages are sent *from* the client for a provisioning connection; all the
/// interesting functionality is in the events delivered to the ``ProvisioningConnectionListener``.
public class ProvisioningConnection: NativeHandleOwner<
    SignalMutPointerProvisioningChatConnection
>, @unchecked Sendable
{
    internal let tokioAsyncContext: TokioAsyncContext

    /// Initiates establishing of the underlying unauthenticated connection to the Chat Service. Once
    /// the connection is established, the returned object can be used to receive messages
    /// after ``ProvisioningChatConnection/start(listener:)`` is called.
    internal init(
        tokioAsyncContext: TokioAsyncContext,
        connectionManager: ConnectionManager,
    ) async throws {
        let nativeHandle = try await tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            connectionManager.withNativeHandle { connectionManager in
                signal_provisioning_chat_connection_connect(
                    promise,
                    tokioAsyncContext.const(),
                    connectionManager.const(),
                )
            }
        }
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: NonNull(nativeHandle)!)
    }

    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerProvisioningChatConnection>
    ) -> SignalFfiErrorRef? {
        return signal_provisioning_chat_connection_destroy(handle.pointer)
    }

    internal required init(owned handle: NonNull<SignalMutPointerProvisioningChatConnection>) {
        fatalError("should not be called directly for a ProvisioningConnection")
    }

    internal init(
        fakeHandle handle: NonNull<SignalMutPointerProvisioningChatConnection>,
        tokioAsyncContext: TokioAsyncContext
    ) {
        self.tokioAsyncContext = tokioAsyncContext
        super.init(owned: handle)
    }

    /// Sets the listener and starts the background thread that handles communication.
    ///
    /// This must be called exactly once for the ``ProvisioningConnection``
    /// to be used.
    public func start(listener: any ProvisioningConnectionListener) {
        withNativeHandle { connectionHandle in
            var listenerStruct = ProvisioningListenerBridge(connection: self, listener: listener)
                .makeListenerStruct()
            withUnsafePointer(to: &listenerStruct) {
                failOnError(
                    signal_provisioning_chat_connection_init_listener(
                        connectionHandle.const(),
                        SignalConstPointerFfiProvisioningListenerStruct(raw: $0)
                    )
                )
            }
        }
    }

    /// Initiates termination of the underlying connection to the Chat Service.
    ///
    /// Returns when the disconnection is complete.
    public func disconnect() async throws {
        _ = try await self.tokioAsyncContext.invokeAsyncFunction { promise, tokioAsyncContext in
            withNativeHandle { chatConnection in
                signal_provisioning_chat_connection_disconnect(
                    promise,
                    tokioAsyncContext.const(),
                    chatConnection.const()
                )
            }
        }
    }

    /// Returns an object representing information about the connection.
    public func info() -> ConnectionInfo {
        withNativeHandle { chatConnection in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_provisioning_chat_connection_info($0, chatConnection.const())
                }
            }
        }
    }
}

extension SignalMutPointerProvisioningChatConnection: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerProvisioningChatConnection

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

extension SignalConstPointerProvisioningChatConnection: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

internal class ProvisioningListenerBridge {
    private class AckHandleOwner: NativeHandleOwner<SignalMutPointerServerMessageAck> {
        override class func destroyNativeHandle(
            _ handle: NonNull<SignalMutPointerServerMessageAck>
        ) -> SignalFfiErrorRef? {
            signal_server_message_ack_destroy(handle.pointer)
        }
    }

    internal weak var connection: ProvisioningConnection?
    private let listener: any ProvisioningConnectionListener

    internal init(
        connection: ProvisioningConnection,
        listener: any ProvisioningConnectionListener
    ) {
        self.connection = connection
        self.listener = listener
    }

    internal init(
        connectionListenerForTesting listener: any ProvisioningConnectionListener
    ) {
        self.listener = listener
    }

    /// Creates an **owned** callback struct from this object.
    ///
    /// The resulting struct must eventually have its `destroy` callback invoked with its `ctx` as argument,
    /// or the ProvisioningListenerBridge object used to construct it (`self`) will be leaked.
    func makeListenerStruct() -> SignalFfiProvisioningListenerStruct {
        let receivedAddress: SignalFfiProvisioningListenerReceivedAddress = { rawCtx, rawAddress, ackHandle in
            defer { signal_free_string(rawAddress) }
            let bridge = Unmanaged<ProvisioningListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()

            let ackHandleOwner = AckHandleOwner(owned: NonNull(ackHandle)!)
            guard let connection = bridge.connection else {
                // The client no longer listening is not an error.
                return 0
            }

            let address = String(cString: rawAddress!)
            bridge.listener.provisioningConnection(connection, didReceiveAddress: address) {
                _ = ackHandleOwner.withNativeHandle { ackHandle in signal_server_message_ack_send(ackHandle.const()) }
            }
            return 0
        }

        let receivedEnvelope: SignalFfiProvisioningListenerReceivedEnvelope = { rawCtx, envelope, ackHandle in
            let bridge = Unmanaged<ProvisioningListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()

            let ackHandleOwner = AckHandleOwner(owned: NonNull(ackHandle)!)
            let envelopeData = Data(consuming: envelope)
            guard let connection = bridge.connection else {
                // The client no longer listening is not an error.
                return 0
            }

            bridge.listener.provisioningConnection(connection, didReceiveEnvelope: envelopeData) {
                _ = ackHandleOwner.withNativeHandle { ackHandle in signal_server_message_ack_send(ackHandle.const()) }
            }
            return 0
        }
        let connectionInterrupted: SignalFfiProvisioningListenerConnectionInterrupted = { rawCtx, maybeError in
            let bridge = Unmanaged<ProvisioningListenerBridge>.fromOpaque(rawCtx!).takeUnretainedValue()
            let error = convertError(maybeError)

            guard let connection = bridge.connection else {
                // The client no longer listening is not an error.
                return 0
            }

            bridge.listener.connectionWasInterrupted(connection, error: error)
            return 0
        }
        return .init(
            ctx: Unmanaged.passRetained(self).toOpaque(),
            received_address: receivedAddress,
            received_envelope: receivedEnvelope,
            connection_interrupted: connectionInterrupted,
            destroy: { rawCtx in
                _ = Unmanaged<AnyObject>.fromOpaque(rawCtx!).takeRetainedValue()
            }
        )
    }
}
