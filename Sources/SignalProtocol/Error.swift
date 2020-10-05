import SignalFfi
import Foundation

public enum SignalError : Error {
    case invalidState(String)
    case internalError(String)
    case nullParameter(String)
    case invalidArgument(String)
    case invalidType(String)
    case invalidUtf8String(String)
    case insufficientOutputSize(String)
    case protobufError(String)
    case invalidCiphertext(String)
    case legacyCiphertextVersion(String)
    case unknownCiphertextVersion(String)
    case unrecognizedMessageVersion(String)
    case invalidMessage(String)
    case invalidKey(String)
    case invalidSignature(String)
    case fingerprintIdentifierMismatch(String)
    case fingerprintVersionMismatch(String)
    case untrustedIdentity(String)
    case invalidKeyIdentifier(String)
    case sessionNotFound(String)
    case duplicatedMessage(String)
    case callbackError(String)
    case unknown(UInt32, String)
}

typealias SignalFfiErrorRef = OpaquePointer

func CheckError(_ error: SignalFfiErrorRef?) throws {
    guard let error = error else { return }

    let err_type = signal_error_get_type(error)
    // If this actually throws we'd have an infinite loop before we hit the 'try!'.
    let err_str = try! invokeFnReturningString {
        signal_error_get_message(error, $0)
    }
    signal_error_free(error)

    switch SignalErrorCode(err_type) {
    case SignalErrorCode_InvalidState:
        throw SignalError.invalidState(err_str)
    case SignalErrorCode_InternalError:
        throw SignalError.internalError(err_str)
    case SignalErrorCode_NullParameter:
        throw SignalError.nullParameter(err_str)
    case SignalErrorCode_InvalidArgument:
        throw SignalError.invalidArgument(err_str)
    case SignalErrorCode_InvalidType:
        throw SignalError.invalidType(err_str)
    case SignalErrorCode_InvalidUtf8String:
        throw SignalError.invalidUtf8String(err_str)
    case SignalErrorCode_InsufficientOutputSize:
        throw SignalError.insufficientOutputSize(err_str)
    case SignalErrorCode_ProtobufError:
        throw SignalError.protobufError(err_str)
    case SignalErrorCode_InvalidCiphertext:
        throw SignalError.invalidCiphertext(err_str)
    case SignalErrorCode_LegacyCiphertextVersion:
        throw SignalError.legacyCiphertextVersion(err_str)
    case SignalErrorCode_UnknownCiphertextVersion:
        throw SignalError.unknownCiphertextVersion(err_str)
    case SignalErrorCode_UnrecognizedMessageVersion:
        throw SignalError.unrecognizedMessageVersion(err_str)
    case SignalErrorCode_InvalidMessage:
        throw SignalError.invalidMessage(err_str)
    case SignalErrorCode_InvalidKey:
        throw SignalError.invalidKey(err_str)
    case SignalErrorCode_InvalidSignature:
        throw SignalError.invalidSignature(err_str)
    case SignalErrorCode_FingerprintIdentifierMismatch:
        throw SignalError.fingerprintIdentifierMismatch(err_str)
    case SignalErrorCode_FingerprintVersionMismatch:
        throw SignalError.fingerprintVersionMismatch(err_str)
    case SignalErrorCode_UntrustedIdentity:
        throw SignalError.untrustedIdentity(err_str)
    case SignalErrorCode_InvalidKeyIdentifier:
        throw SignalError.invalidKeyIdentifier(err_str)
    case SignalErrorCode_SessionNotFound:
        throw SignalError.sessionNotFound(err_str)
    case SignalErrorCode_DuplicatedMessage:
        throw SignalError.duplicatedMessage(err_str)
    case SignalErrorCode_CallbackError:
        throw SignalError.callbackError(err_str)
    default:
        throw SignalError.unknown(err_type, err_str)
    }
}
