//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

///
/// Cds2Client provides bindings to interact with Signal's v2 Contact Discovery Service.
///
/// Interaction with the service is done over a websocket, which is handled by the client.  Once the websocket
/// has been initiated, the client establishes a connection in the following manner:
///
/// <ul>
///     <li>connect to the service websocket, read service attestation message</li>
///     <li>instantiate Cds2Client with the attestation message</li>
///     <li>send Cds2Client.initialRequest()</li>
///     <li>receive a response and pass to Cds2Client.completeHandshake()</li>
/// </ul>
///
/// After a connection has been established, a client may send or receive messages.  To send a message, they
/// formulate the plaintext, then pass it to Cds2Client.establishedSend() to get the ciphertext message
/// to pass along.  When a message is received (as ciphertext), it is passed to Cds2Client.establishedRecv(),
/// which decrypts and verifies it, passing the plaintext back to the client for processing.
///
/// A future update to Cds2Client will implement additional parts of the contact discovery protocol.
///
public class Cds2Client: NativeHandleOwner {

    public convenience init<MrenclaveBytes, AttestationBytes>(mrenclave: MrenclaveBytes, attestationMessage: AttestationBytes, currentDate: Date) throws
        where MrenclaveBytes: ContiguousBytes, AttestationBytes: ContiguousBytes {
        let handle: OpaquePointer? = try attestationMessage.withUnsafeBorrowedBuffer { attestationMessageBuffer in
            try mrenclave.withUnsafeBorrowedBuffer { mrenclaveBuffer in
                var result: OpaquePointer?
                try checkError(signal_cds2_client_state_new(&result,
                        mrenclaveBuffer,
                        attestationMessageBuffer,
                        UInt64(currentDate.timeIntervalSince1970 * 1000)))
                return result
            }
        }

        self.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_cds2_client_state_destroy(handle)
    }

    /// Initial request to send to CDS 2, which begins post-attestation handshake.
    public func initialRequest() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_cds2_client_state_initial_request($0, $1, nativeHandle)
                }
            }
        }
    }

    /// Called by client upon receipt of first non-attestation message from service, to complete handshake.
    public func completeHandshake<Bytes: ContiguousBytes>(_ handshakeResponse: Bytes) throws {
        try withNativeHandle { nativeHandle in
            try handshakeResponse.withUnsafeBorrowedBuffer { buffer in
                try checkError(signal_cds2_client_state_complete_handshake(nativeHandle, buffer))
            }
        }
    }

    /// Called by client after completeHandshake has succeeded, to encrypt a message to send.
    public func establishedSend<Bytes: ContiguousBytes>(_ plaintextToSend: Bytes) throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try plaintextToSend.withUnsafeBorrowedBuffer { buffer in
                try invokeFnReturningArray {
                    signal_cds2_client_state_established_send($0, $1, nativeHandle, buffer)
                }
            }
        }
    }

    /// Called by client after completeHandshake has succeeded, to decrypt a received message.
    public func establishedRecv<Bytes: ContiguousBytes>(_ receivedCiphertext: Bytes) throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try receivedCiphertext.withUnsafeBorrowedBuffer { buffer in
                try invokeFnReturningArray {
                    signal_cds2_client_state_established_recv($0, $1, nativeHandle, buffer)
                }
            }
        }
    }
}
