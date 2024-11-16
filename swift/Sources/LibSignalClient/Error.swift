//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

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
    case invalidAttestationData(String)
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
    case nicknameCannotBeEmpty(String)
    case nicknameCannotStartWithDigit(String)
    case missingSeparator(String)
    case badDiscriminatorCharacter(String)
    case badNicknameCharacter(String)
    case nicknameTooShort(String)
    case nicknameTooLong(String)
    case usernameLinkInvalidEntropyDataLength(String)
    case usernameLinkInvalid(String)
    case usernameDiscriminatorCannotBeEmpty(String)
    case usernameDiscriminatorCannotBeZero(String)
    case usernameDiscriminatorCannotBeSingleDigit(String)
    case usernameDiscriminatorCannotHaveLeadingZeros(String)
    case usernameDiscriminatorTooLarge(String)
    case ioError(String)
    case invalidMediaInput(String)
    case unsupportedMediaInput(String)
    case callbackError(String)
    case webSocketError(String)
    case connectionTimeoutError(String)
    case connectionFailed(String)
    case networkProtocolError(String)
    case cdsiInvalidToken(String)
    case rateLimitedError(retryAfter: TimeInterval, message: String)
    case svrDataMissing(String)
    case svrRestoreFailed(triesRemaining: UInt32, message: String)
    case svrRotationMachineTooManySteps(String)
    case chatServiceInactive(String)
    case chatServiceIntentionallyDisconnected(String)
    case appExpired(String)
    case deviceDeregistered(String)

    case unknown(UInt32, String)
}

internal typealias SignalFfiErrorRef = OpaquePointer

internal func convertError(_ error: SignalFfiErrorRef?) -> Error? {
    // It would be *slightly* more efficient for checkError to call convertError,
    // instead of the other way around. However, then it would be harder to implement
    // checkError, since some of the conversion operations can themselves throw.
    // So this is more maintainable.
    do {
        try checkError(error)
        return nil
    } catch let thrownError {
        return thrownError
    }
}

internal func checkError(_ error: SignalFfiErrorRef?) throws {
    guard let error = error else { return }

    let errType = signal_error_get_type(error)
    // If this actually throws we'd have an infinite loop before we hit the 'try!'.
    let errStr = try! invokeFnReturningString {
        signal_error_get_message(error, $0)
    }
    defer { signal_error_free(error) }

    switch SignalErrorCode(errType) {
    case SignalErrorCodeCancelled:
        // Special case: don't use SignalError for this one.
        throw CancellationError()
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
    case SignalErrorCodeInvalidAttestationData:
        throw SignalError.invalidAttestationData(errStr)
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
        throw SignalError.nicknameCannotBeEmpty(errStr)
    case SignalErrorCodeUsernameCannotStartWithDigit:
        throw SignalError.nicknameCannotStartWithDigit(errStr)
    case SignalErrorCodeUsernameMissingSeparator:
        throw SignalError.missingSeparator(errStr)
    case SignalErrorCodeUsernameBadDiscriminatorCharacter:
        throw SignalError.badDiscriminatorCharacter(errStr)
    case SignalErrorCodeUsernameBadNicknameCharacter:
        throw SignalError.badNicknameCharacter(errStr)
    case SignalErrorCodeUsernameTooShort:
        throw SignalError.nicknameTooShort(errStr)
    case SignalErrorCodeUsernameTooLong:
        throw SignalError.nicknameTooLong(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotBeEmpty:
        throw SignalError.usernameDiscriminatorCannotBeEmpty(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotBeZero:
        throw SignalError.usernameDiscriminatorCannotBeZero(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotBeSingleDigit:
        throw SignalError.usernameDiscriminatorCannotBeSingleDigit(errStr)
    case SignalErrorCodeUsernameDiscriminatorCannotHaveLeadingZeros:
        throw SignalError.usernameDiscriminatorCannotHaveLeadingZeros(errStr)
    case SignalErrorCodeUsernameDiscriminatorTooLarge:
        throw SignalError.usernameDiscriminatorTooLarge(errStr)
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
    case SignalErrorCodeWebSocket:
        throw SignalError.webSocketError(errStr)
    case SignalErrorCodeConnectionTimedOut:
        throw SignalError.connectionTimeoutError(errStr)
    case SignalErrorCodeConnectionFailed:
        throw SignalError.connectionFailed(errStr)
    case SignalErrorCodeNetworkProtocol:
        throw SignalError.networkProtocolError(errStr)
    case SignalErrorCodeCdsiInvalidToken:
        throw SignalError.cdsiInvalidToken(errStr)
    case SignalErrorCodeRateLimited:
        let retryAfterSeconds = try invokeFnReturningInteger {
            signal_error_get_retry_after_seconds(error, $0)
        }
        throw SignalError.rateLimitedError(retryAfter: TimeInterval(retryAfterSeconds), message: errStr)
    case SignalErrorCodeSvrDataMissing:
        throw SignalError.svrDataMissing(errStr)
    case SignalErrorCodeSvrRestoreFailed:
        let triesRemaining = try invokeFnReturningInteger {
            signal_error_get_tries_remaining(error, $0)
        }
        throw SignalError.svrRestoreFailed(triesRemaining: triesRemaining, message: errStr)
    case SignalErrorCodeSvrRotationMachineTooManySteps:
        throw SignalError.svrRotationMachineTooManySteps(errStr)
    case SignalErrorCodeChatServiceInactive:
        throw SignalError.chatServiceInactive(errStr)
    case SignalErrorCodeChatServiceIntentionallyDisconnected:
        throw SignalError.chatServiceIntentionallyDisconnected(errStr)
    case SignalErrorCodeAppExpired:
        throw SignalError.appExpired(errStr)
    case SignalErrorCodeDeviceDeregistered:
        throw SignalError.deviceDeregistered(errStr)
    case SignalErrorCodeBackupValidation:
        let unknownFields = try invokeFnReturningStringArray {
            signal_error_get_unknown_fields(error, $0)
        }
        // Special case: we have a dedicated type for this one.
        throw MessageBackupValidationError(
            errorMessage: errStr,
            unknownFields: MessageBackupUnknownFields(fields: unknownFields)
        )
    default:
        throw SignalError.unknown(errType, errStr)
    }
}

internal func failOnError(_ error: SignalFfiErrorRef?) {
    failOnError { try checkError(error) }
}

internal func failOnError<Result>(_ fn: () throws -> Result, file: StaticString = #file, line: UInt32 = #line) -> Result {
    do {
        return try fn()
    } catch {
        guard let loggerBridge = LoggerBridge.shared else {
            fatalError("unexpected error: \(error)", file: file, line: UInt(line))
        }
        "unexpected error: \(error)".withCString {
            loggerBridge.logger.logFatal(file: String(describing: file), line: line, message: $0)
        }
    }
}
