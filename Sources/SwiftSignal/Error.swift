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

func CheckError(_ error: OpaquePointer?) throws {
    if error != nil {
        let err_type = signal_error_get_type(error)
        let err_str = try invokeFnReturningString(fn: { (b) in signal_error_get_message(error, b) })
        signal_error_free(error)

        // FIXME: Swift is willing to import the SIGNAL_ERROR_CODE_xxx
        // values, and we can compare them to each other but cannot
        // get their integer values without reflection - is there
        // some other way?

        switch err_type {
        case 2:
            throw SignalError.invalid_state(err_str)
        case 3:
            throw SignalError.internal_error(err_str)
        case 4:
            throw SignalError.null_parameter(err_str)
        case 5:
            throw SignalError.invalid_argument(err_str)
        case 6:
            throw SignalError.invalid_type(err_str)
        case 7:
            throw SignalError.invalid_utf8_string(err_str)
        case 8:
            throw SignalError.insufficient_output_size(err_str)
        case 10:
            throw SignalError.protobuf_error(err_str)
        case 20:
            throw SignalError.invalid_ciphertext(err_str)
        case 21:
            throw SignalError.legacy_ciphertext_version(err_str)
        case 22:
            throw SignalError.unknown_ciphertext_version(err_str)
        case 23:
            throw SignalError.unrecognized_message_version(err_str)
        case 30:
            throw SignalError.invalid_message(err_str)
        case 40:
            throw SignalError.invalid_key(err_str)
        case 41:
            throw SignalError.invalid_signature(err_str)
        case 50:
            throw SignalError.fingerprint_identifier_mismatch(err_str)
        case 51:
            throw SignalError.fingerprint_version_mismatch(err_str)
        case 60:
            throw SignalError.untrusted_identity(err_str)
        case 70:
            throw SignalError.invalid_key_identifier(err_str)
        case 80:
            throw SignalError.session_not_found(err_str)
        case 90:
            throw SignalError.duplicated_message(err_str)
        case 100:
            throw SignalError.callback_error(err_str)
        default:
            throw SignalError.unknown(err_type, err_str)
        }
    }
}
