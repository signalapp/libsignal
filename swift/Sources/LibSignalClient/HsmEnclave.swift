//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// The HsmCodeHashList is a wrapper around a flat UInt8 array to make it more
/// convenient to send code hashes to initialize the client.
///
/// A client specifies one or more code signatures it's willing to talk to. These are
/// known as code hashes and are arrays of bytes.
public struct HsmCodeHashList: Sendable {
    var codeHashes: [UInt8]

    public init() {
        self.codeHashes = []
    }

    public mutating func append(_ codeHash: [UInt8]) throws {
        if codeHash.count != 32 {
            fatalError("code hash length must be 32")
        }

        self.codeHashes.append(contentsOf: codeHash)
    }

    func flatten() -> [UInt8] {
        return self.codeHashes
    }
}

///
/// HsmEnclaveClient provides bindings to interact with Signal's HSM-backed enclave.
///
/// Interaction with the enclave is done over a websocket, which is handled by the client.  Once the websocket
/// has been initiated, the client establishes a connection in the following manner:
///
/// <ul>
///     <li>send HsmEnclaveClient.initialRequest()</li>
///     <li>receive a response and pass to HsmEnclaveClient.completeHandshake()</li>
/// </ul>
///
/// After a connection has been established, a client may send or receive messages.  To send a message, they
/// formulate the plaintext, then pass it to HsmEnclaveClient.establishedSend() to get the ciphertext message
/// to pass along.  When a message is received (as ciphertext), it is passed to HsmEnclaveClient.establishedRecv(),
/// which decrypts and verifies it, passing the plaintext back to the client for processing.
///
public class HsmEnclaveClient: NativeHandleOwner {
    public convenience init<Bytes: ContiguousBytes>(publicKey: Bytes, codeHashes: HsmCodeHashList) throws {
        let codeHashBytes = codeHashes.flatten()

        let handle: OpaquePointer? = try publicKey.withUnsafeBorrowedBuffer { publicKeyBuffer in
            try codeHashBytes.withUnsafeBorrowedBuffer { codeHashBuffer in
                var result: OpaquePointer?
                try checkError(signal_hsm_enclave_client_new(
                    &result,
                    publicKeyBuffer,
                    codeHashBuffer
                ))
                return result
            }
        }

        self.init(owned: handle!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_hsm_enclave_client_destroy(handle)
    }

    /// Initial request to send to HSM enclave, to begin handshake.
    public func initialRequest() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_hsm_enclave_client_initial_request($0, nativeHandle)
                }
            }
        }
    }

    /// Called by client upon receipt of first message from HSM enclave, to complete handshake.
    public func completeHandshake<Bytes: ContiguousBytes>(_ handshakeResponse: Bytes) throws {
        try withNativeHandle { nativeHandle in
            try handshakeResponse.withUnsafeBorrowedBuffer { buffer in
                try checkError(signal_hsm_enclave_client_complete_handshake(nativeHandle, buffer))
            }
        }
    }

    /// Called by client after completeHandshake has succeeded, to encrypt a message to send.
    public func establishedSend<Bytes: ContiguousBytes>(_ plaintextToSend: Bytes) throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try plaintextToSend.withUnsafeBorrowedBuffer { buffer in
                try invokeFnReturningArray {
                    signal_hsm_enclave_client_established_send($0, nativeHandle, buffer)
                }
            }
        }
    }

    /// Called by client after completeHandshake has succeeded, to decrypt a received message.
    public func establishedRecv<Bytes: ContiguousBytes>(_ receivedCiphertext: Bytes) throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try receivedCiphertext.withUnsafeBorrowedBuffer { buffer in
                try invokeFnReturningArray {
                    signal_hsm_enclave_client_established_recv($0, nativeHandle, buffer)
                }
            }
        }
    }
}
