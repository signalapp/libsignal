//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

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
    case invalidSession(String)
    case invalidRegistrationId(address: ProtocolAddress, message: String)
    case invalidSenderKeySession(distributionId: UUID, message: String)
    case duplicatedMessage(String)
    case verificationFailed(String)
    case cannotBeEmpty(String)
    case cannotStartWithDigit(String)
    case missingSeparator(String)
    case badDiscriminator(String)
    case badNicknameCharacter(String)
    case nicknameTooShort(String)
    case nicknameTooLong(String)
    case usernameLinkInvalidEntropyDataLength(String)
    case usernameLinkInvalid(String)
    case ioError(String)
    case invalidMediaInput(String)
    case unsupportedMediaInput(String)
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
    case SignalErrorCodeInvalidState:
        throw SignalError.invalidState(errStr)
    case SignalErrorCodeInternalError:
        throw SignalError.internalError(errStr)
    case SignalErrorCodeNullParameter:
        throw SignalError.nullParameter(errStr)
    case SignalErrorCodeInvalidArgument:
        throw SignalError.invalidArgument(errStr)
    case SignalErrorCodeInvalidType:
        throw SignalError.invalidType(errStr)
    case SignalErrorCodeInvalidUtf8String:
        throw SignalError.invalidUtf8String(errStr)
    case SignalErrorCodeProtobufError:
        throw SignalError.protobufError(errStr)
    case SignalErrorCodeLegacyCiphertextVersion:
        throw SignalError.legacyCiphertextVersion(errStr)
    case SignalErrorCodeUnknownCiphertextVersion:
        throw SignalError.unknownCiphertextVersion(errStr)
    case SignalErrorCodeUnrecognizedMessageVersion:
        throw SignalError.unrecognizedMessageVersion(errStr)
    case SignalErrorCodeInvalidMessage:
        throw SignalError.invalidMessage(errStr)
    case SignalErrorCodeFingerprintParsingError:
        throw SignalError.fingerprintParsingError(errStr)
    case SignalErrorCodeSealedSenderSelfSend:
        throw SignalError.sealedSenderSelfSend(errStr)
    case SignalErrorCodeInvalidKey:
        throw SignalError.invalidKey(errStr)
    case SignalErrorCodeInvalidSignature:
        throw SignalError.invalidSignature(errStr)
    case SignalErrorCodeFingerprintVersionMismatch:
        throw SignalError.fingerprintVersionMismatch(errStr)
    case SignalErrorCodeUntrustedIdentity:
        throw SignalError.untrustedIdentity(errStr)
    case SignalErrorCodeInvalidKeyIdentifier:
        throw SignalError.invalidKeyIdentifier(errStr)
    case SignalErrorCodeSessionNotFound:
        throw SignalError.sessionNotFound(errStr)
    case SignalErrorCodeInvalidSession:
        throw SignalError.invalidSession(errStr)
    case SignalErrorCodeInvalidRegistrationId:
        let address: ProtocolAddress = try invokeFnReturningNativeHandle {
            signal_error_get_address(error, $0)
        }
        throw SignalError.invalidRegistrationId(address: address, message: errStr)
    case SignalErrorCodeInvalidSenderKeySession:
        let distributionId = try invokeFnReturningUuid {
            signal_error_get_uuid(error, $0)
        }
        throw SignalError.invalidSenderKeySession(distributionId: distributionId, message: errStr)
    case SignalErrorCodeDuplicatedMessage:
        throw SignalError.duplicatedMessage(errStr)
    case SignalErrorCodeVerificationFailure:
        throw SignalError.verificationFailed(errStr)
    case SignalErrorCodeUsernameCannotBeEmpty:
        throw SignalError.cannotBeEmpty(errStr)
    case SignalErrorCodeUsernameCannotStartWithDigit:
        throw SignalError.cannotStartWithDigit(errStr)
    case SignalErrorCodeUsernameMissingSeparator:
        throw SignalError.missingSeparator(errStr)
    case SignalErrorCodeUsernameBadDiscriminator:
        throw SignalError.badDiscriminator(errStr)
    case SignalErrorCodeUsernameBadCharacter:
        throw SignalError.badNicknameCharacter(errStr)
    case SignalErrorCodeUsernameTooShort:
        throw SignalError.nicknameTooShort(errStr)
    case SignalErrorCodeUsernameTooLong:
        throw SignalError.nicknameTooLong(errStr)
    case SignalErrorCodeUsernameLinkInvalidEntropyDataLength:
        throw SignalError.usernameLinkInvalidEntropyDataLength(errStr)
    case SignalErrorCodeUsernameLinkInvalid:
        throw SignalError.usernameLinkInvalid(errStr)
    case SignalErrorCodeIoError:
        throw SignalError.ioError(errStr)
    case SignalErrorCodeInvalidMediaInput:
        throw SignalError.invalidMediaInput(errStr)
    case SignalErrorCodeUnsupportedMediaInput:
        throw SignalError.unsupportedMediaInput(errStr)
    case SignalErrorCodeCallbackError:
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
