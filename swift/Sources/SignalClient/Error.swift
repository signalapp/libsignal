//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

#if canImport(SignalCoreKit)
import SignalCoreKit
#endif

public enum SignalError: Error {
    case invalidState(String)
    case internalError(String)
    case nullParameter(String)
    case invalidArgument(String)
    case invalidType(String)
    case invalidUtf8String(String)
    case protobufError(String)
    case invalidCiphertext(String)
    case legacyCiphertextVersion(String)
    case unknownCiphertextVersion(String)
    case unrecognizedMessageVersion(String)
    case invalidMessage(String)
    case invalidKey(String)
    case invalidSignature(String)
    case fingerprintVersionMismatch(String)
    case fingerprintParsingError(String)
    case sealedSenderSelfSend(String)
    case untrustedIdentity(String)
    case invalidKeyIdentifier(String)
    case sessionNotFound(String)
    case invalidRegistrationId(address: ProtocolAddress, message: String)
    case duplicatedMessage(String)
    case verificationFailed(String)
    case callbackError(String)
    case unknown(UInt32, String)
}

internal typealias SignalFfiErrorRef = OpaquePointer

internal func checkError(_ error: SignalFfiErrorRef?) throws {
    guard let error = error else { return }

    let errType = signal_error_get_type(error)
    // If this actually throws we'd have an infinite loop before we hit the 'try!'.
    let errStr = try! invokeFnReturningString {
        signal_error_get_message(error, $0)
    }
    defer { signal_error_free(error) }

    switch SignalErrorCode(errType) {
    case SignalErrorCode_InvalidState:
        throw SignalError.invalidState(errStr)
    case SignalErrorCode_InternalError:
        throw SignalError.internalError(errStr)
    case SignalErrorCode_NullParameter:
        throw SignalError.nullParameter(errStr)
    case SignalErrorCode_InvalidArgument:
        throw SignalError.invalidArgument(errStr)
    case SignalErrorCode_InvalidType:
        throw SignalError.invalidType(errStr)
    case SignalErrorCode_InvalidUtf8String:
        throw SignalError.invalidUtf8String(errStr)
    case SignalErrorCode_ProtobufError:
        throw SignalError.protobufError(errStr)
    case SignalErrorCode_InvalidCiphertext:
        throw SignalError.invalidCiphertext(errStr)
    case SignalErrorCode_LegacyCiphertextVersion:
        throw SignalError.legacyCiphertextVersion(errStr)
    case SignalErrorCode_UnknownCiphertextVersion:
        throw SignalError.unknownCiphertextVersion(errStr)
    case SignalErrorCode_UnrecognizedMessageVersion:
        throw SignalError.unrecognizedMessageVersion(errStr)
    case SignalErrorCode_InvalidMessage:
        throw SignalError.invalidMessage(errStr)
    case SignalErrorCode_FingerprintParsingError:
        throw SignalError.fingerprintParsingError(errStr)
    case SignalErrorCode_SealedSenderSelfSend:
        throw SignalError.sealedSenderSelfSend(errStr)
    case SignalErrorCode_InvalidKey:
        throw SignalError.invalidKey(errStr)
    case SignalErrorCode_InvalidSignature:
        throw SignalError.invalidSignature(errStr)
    case SignalErrorCode_FingerprintVersionMismatch:
        throw SignalError.fingerprintVersionMismatch(errStr)
    case SignalErrorCode_UntrustedIdentity:
        throw SignalError.untrustedIdentity(errStr)
    case SignalErrorCode_InvalidKeyIdentifier:
        throw SignalError.invalidKeyIdentifier(errStr)
    case SignalErrorCode_SessionNotFound:
        throw SignalError.sessionNotFound(errStr)
    case SignalErrorCode_InvalidRegistrationId:
        let address: ProtocolAddress = try invokeFnReturningNativeHandle {
            signal_error_get_address(error, $0)
        }
        throw SignalError.invalidRegistrationId(address: address, message: errStr)
    case SignalErrorCode_DuplicatedMessage:
        throw SignalError.duplicatedMessage(errStr)
    case SignalErrorCode_VerificationFailure:
        throw SignalError.verificationFailed(errStr)
    case SignalErrorCode_CallbackError:
        throw SignalError.callbackError(errStr)
    default:
        throw SignalError.unknown(errType, errStr)
    }
}

internal func failOnError(_ error: SignalFfiErrorRef?) {
    failOnError { try checkError(error) }
}

internal func failOnError<Result>(_ fn: () throws -> Result) -> Result {
#if canImport(SignalCoreKit)
    do {
        return try fn()
    } catch {
        owsFail("unexpected error: \(error)")
    }
#else
    return try! fn()
#endif
}
