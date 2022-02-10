//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

/// The HsmCodeHashList is a wrapper around a flat UInt8 array to make it more
/// convenient to send code hashes to initialize the client.
///
/// A client specifies one or more code signatures it's willing to talk to. These are
/// known as code hashes and are arrays of bytes.
public struct HsmCodeHashList {
    var codeHashes: [UInt8]

    public init() {
        codeHashes = []
    }

    public mutating func append(_ codeHash: [UInt8]) throws {
        if codeHash.count != 32 {
            fatalError("code hash length must be 32")
        }

        codeHashes.append(contentsOf: codeHash)
    }

    func flatten() -> [UInt8] {
        return codeHashes
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

        let handle: OpaquePointer? = try publicKey.withUnsafeBytes { publicKeyBytes in
            try codeHashBytes.withUnsafeBytes { codeHashBytes in
                var result: OpaquePointer?
                try checkError(signal_hsm_enclave_client_new(&result,
                                                             publicKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                             publicKeyBytes.count,
                                                             codeHashBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                             codeHashBytes.count))
                return result
            }
        }

        self.init(owned: handle!)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_hsm_enclave_client_destroy(handle)
    }

    /// Initial request to send to HSM enclave, to begin handshake.
    public func initialRequest() throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningArray {
                signal_hsm_enclave_client_initial_request($0, $1, nativeHandle)
            }
        }
    }

    /// Called by client upon receipt of first message from HSM enclave, to complete handshake.
    public func completeHandshake<Bytes: ContiguousBytes>(_ handshakeResponse: Bytes) throws {
        try withNativeHandle { nativeHandle in
            try handshakeResponse.withUnsafeBytes { bytes in
                try checkError(signal_hsm_enclave_client_complete_handshake(nativeHandle, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count))
            }
        }
    }

    /// Called by client after completeHandshake has succeeded, to encrypt a message to send.
    public func establishedSend<Bytes: ContiguousBytes>(_ plaintextToSend: Bytes) throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try plaintextToSend.withUnsafeBytes { bytes in
                try invokeFnReturningArray {
                    signal_hsm_enclave_client_established_send($0, $1, nativeHandle, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count)
                }
            }
        }
    }

    /// Called by client after completeHandshake has succeeded, to decrypt a received message.
    public func establishedRecv<Bytes: ContiguousBytes>(_ receivedCiphertext: Bytes) throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try receivedCiphertext.withUnsafeBytes { bytes in
                try invokeFnReturningArray {
                    signal_hsm_enclave_client_established_recv($0, $1, nativeHandle, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), bytes.count)
                }
            }
        }
    }
}
