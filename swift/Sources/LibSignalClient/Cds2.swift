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

    private convenience init<MrenclaveBytes, CertBytes, AttestationBytes>(mrenclave: MrenclaveBytes, trustedCaCert: CertBytes, attestationMessage: AttestationBytes, earliestValidDate: Date) throws
        where MrenclaveBytes: ContiguousBytes, CertBytes: ContiguousBytes, AttestationBytes: ContiguousBytes {
        let handle: OpaquePointer? = try attestationMessage.withUnsafeBorrowedBuffer { attestationMessageBuffer in
            try trustedCaCert.withUnsafeBorrowedBuffer { trustedCaCertBuffer in
                try mrenclave.withUnsafeBorrowedBuffer { mrenclaveBuffer in
                    var result: OpaquePointer?
                    try checkError(signal_cds2_client_state_new(&result,
                            mrenclaveBuffer,
                            trustedCaCertBuffer,
                            attestationMessageBuffer,
                            UInt64(earliestValidDate.timeIntervalSince1970 * 1000)))
                    return result
                }
            }
        }

        self.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_cds2_client_state_destroy(handle)
    }

    /// Until attestation verification is fully implemented, this client must not be used in production builds
    public static func create_NOT_FOR_PRODUCTION<Bytes1: ContiguousBytes, Bytes2: ContiguousBytes, Bytes3: ContiguousBytes>(_ mrenclave: Bytes1, trustedCaCertBytes: Bytes2, attestationMessage: Bytes3, earliestValidDate: Date) throws -> Cds2Client {
        return try Cds2Client(mrenclave: mrenclave, trustedCaCert: trustedCaCertBytes, attestationMessage: attestationMessage, earliestValidDate: earliestValidDate)
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
