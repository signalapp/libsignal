import SignalFfi
import Foundation

public enum SignalError : Error {
    case invalid_state(String)
    case internal_error(String)
    case null_parameter(String)
    case invalid_argument(String)
    case invalid_type(String)
    case invalid_utf8_string(String)
    case insufficient_output_size(String)
    case protobuf_error(String)
    case invalid_ciphertext(String)
    case legacy_ciphertext_version(String)
    case unknown_ciphertext_version(String)
    case unrecognized_message_version(String)
    case invalid_message(String)
    case invalid_key(String)
    case invalid_signature(String)
    case fingerprint_identifier_mismatch(String)
    case fingerprint_version_mismatch(String)
    case untrusted_identity(String)
    case invalid_key_identifier(String)
    case session_not_found(String)
    case duplicated_message(String)
    case callback_error(String)
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
        throw SignalError.invalid_state(err_str)
    case SignalErrorCode_InternalError:
        throw SignalError.internal_error(err_str)
    case SignalErrorCode_NullParameter:
        throw SignalError.null_parameter(err_str)
    case SignalErrorCode_InvalidArgument:
        throw SignalError.invalid_argument(err_str)
    case SignalErrorCode_InvalidType:
        throw SignalError.invalid_type(err_str)
    case SignalErrorCode_InvalidUtf8String:
        throw SignalError.invalid_utf8_string(err_str)
    case SignalErrorCode_InsufficientOutputSize:
        throw SignalError.insufficient_output_size(err_str)
    case SignalErrorCode_ProtobufError:
        throw SignalError.protobuf_error(err_str)
    case SignalErrorCode_InvalidCiphertext:
        throw SignalError.invalid_ciphertext(err_str)
    case SignalErrorCode_LegacyCiphertextVersion:
        throw SignalError.legacy_ciphertext_version(err_str)
    case SignalErrorCode_UnknownCiphertextVersion:
        throw SignalError.unknown_ciphertext_version(err_str)
    case SignalErrorCode_UnrecognizedMessageVersion:
        throw SignalError.unrecognized_message_version(err_str)
    case SignalErrorCode_InvalidMessage:
        throw SignalError.invalid_message(err_str)
    case SignalErrorCode_InvalidKey:
        throw SignalError.invalid_key(err_str)
    case SignalErrorCode_InvalidSignature:
        throw SignalError.invalid_signature(err_str)
    case SignalErrorCode_FingerprintIdentifierMismatch:
        throw SignalError.fingerprint_identifier_mismatch(err_str)
    case SignalErrorCode_FingerprintVersionMismatch:
        throw SignalError.fingerprint_version_mismatch(err_str)
    case SignalErrorCode_UntrustedIdentity:
        throw SignalError.untrusted_identity(err_str)
    case SignalErrorCode_InvalidKeyIdentifier:
        throw SignalError.invalid_key_identifier(err_str)
    case SignalErrorCode_SessionNotFound:
        throw SignalError.session_not_found(err_str)
    case SignalErrorCode_DuplicatedMessage:
        throw SignalError.duplicated_message(err_str)
    case SignalErrorCode_CallbackError:
        throw SignalError.callback_error(err_str)
    default:
        throw SignalError.unknown(err_type, err_str)
    }
}
