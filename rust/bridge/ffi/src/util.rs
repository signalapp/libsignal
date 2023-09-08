//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use attest::hsm_enclave::Error as HsmEnclaveError;
use attest::sgx_session::Error as SgxError;
use device_transfer::Error as DeviceTransferError;
use libsignal_bridge::ffi::*;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

#[derive(Debug)]
#[repr(C)]
pub enum SignalErrorCode {
    #[allow(dead_code)]
    UnknownError = 1,
    InvalidState = 2,
    InternalError = 3,
    NullParameter = 4,
    InvalidArgument = 5,
    InvalidType = 6,
    InvalidUtf8String = 7,

    ProtobufError = 10,

    LegacyCiphertextVersion = 21,
    UnknownCiphertextVersion = 22,
    UnrecognizedMessageVersion = 23,

    InvalidMessage = 30,
    SealedSenderSelfSend = 31,

    InvalidKey = 40,
    InvalidSignature = 41,
    InvalidAttestationData = 42,

    FingerprintVersionMismatch = 51,
    FingerprintParsingError = 52,

    UntrustedIdentity = 60,

    InvalidKeyIdentifier = 70,

    SessionNotFound = 80,
    InvalidRegistrationId = 81,
    InvalidSession = 82,
    InvalidSenderKeySession = 83,

    DuplicatedMessage = 90,

    CallbackError = 100,

    VerificationFailure = 110,

    UsernameCannotBeEmpty = 120,
    UsernameCannotStartWithDigit = 121,
    UsernameMissingSeparator = 122,
    UsernameBadDiscriminator = 123,
    UsernameBadCharacter = 124,
    UsernameTooShort = 125,
    UsernameTooLong = 126,

    UsernameLinkInvalidEntropyDataLength = 127,
    UsernameLinkInvalid = 128,

    IoError = 130,
    #[allow(dead_code)]
    InvalidMediaInput = 131,
    #[allow(dead_code)]
    UnsupportedMediaInput = 132,
}

impl From<&SignalFfiError> for SignalErrorCode {
    fn from(err: &SignalFfiError) -> Self {
        match err {
            SignalFfiError::NullPointer => SignalErrorCode::NullParameter,

            SignalFfiError::UnexpectedPanic(_)
            | SignalFfiError::DeviceTransfer(DeviceTransferError::InternalError(_))
            | SignalFfiError::Signal(SignalProtocolError::FfiBindingError(_)) => {
                SignalErrorCode::InternalError
            }

            SignalFfiError::InvalidUtf8String => SignalErrorCode::InvalidUtf8String,

            SignalFfiError::Signal(SignalProtocolError::InvalidProtobufEncoding) => {
                SignalErrorCode::ProtobufError
            }

            SignalFfiError::Signal(SignalProtocolError::DuplicatedMessage(_, _)) => {
                SignalErrorCode::DuplicatedMessage
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidPreKeyId)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSignedPreKeyId)
            | SignalFfiError::Signal(SignalProtocolError::InvalidKyberPreKeyId) => {
                SignalErrorCode::InvalidKeyIdentifier
            }

            SignalFfiError::Signal(SignalProtocolError::SealedSenderSelfSend) => {
                SignalErrorCode::SealedSenderSelfSend
            }

            SignalFfiError::Signal(SignalProtocolError::SignatureValidationFailed) => {
                SignalErrorCode::InvalidSignature
            }

            SignalFfiError::Signal(SignalProtocolError::NoKeyTypeIdentifier)
            | SignalFfiError::Signal(SignalProtocolError::BadKeyType(_))
            | SignalFfiError::Signal(SignalProtocolError::BadKeyLength(_, _))
            | SignalFfiError::Signal(SignalProtocolError::BadKEMKeyType(_))
            | SignalFfiError::Signal(SignalProtocolError::WrongKEMKeyType(_, _))
            | SignalFfiError::Signal(SignalProtocolError::BadKEMKeyLength(_, _))
            | SignalFfiError::Signal(SignalProtocolError::InvalidMacKeyLength(_))
            | SignalFfiError::DeviceTransfer(DeviceTransferError::KeyDecodingFailed)
            | SignalFfiError::HsmEnclave(HsmEnclaveError::InvalidPublicKeyError)
            | SignalFfiError::SignalCrypto(SignalCryptoError::InvalidKeySize) => {
                SignalErrorCode::InvalidKey
            }

            SignalFfiError::Sgx(SgxError::AttestationDataError { .. }) => {
                SignalErrorCode::InvalidAttestationData
            }

            SignalFfiError::Pin(PinError::Argon2Error(_))
            | SignalFfiError::Pin(PinError::DecodingError(_))
            | SignalFfiError::Pin(PinError::MrenclaveLookupError) => {
                SignalErrorCode::InvalidArgument
            }

            SignalFfiError::Signal(SignalProtocolError::SessionNotFound(_))
            | SignalFfiError::Signal(SignalProtocolError::NoSenderKeyState { .. }) => {
                SignalErrorCode::SessionNotFound
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidRegistrationId(..)) => {
                SignalErrorCode::InvalidRegistrationId
            }

            SignalFfiError::Signal(SignalProtocolError::FingerprintParsingError) => {
                SignalErrorCode::FingerprintParsingError
            }

            SignalFfiError::Signal(SignalProtocolError::FingerprintVersionMismatch(_, _)) => {
                SignalErrorCode::FingerprintVersionMismatch
            }

            SignalFfiError::Signal(SignalProtocolError::UnrecognizedMessageVersion(_))
            | SignalFfiError::Signal(SignalProtocolError::UnknownSealedSenderVersion(_)) => {
                SignalErrorCode::UnrecognizedMessageVersion
            }

            SignalFfiError::Signal(SignalProtocolError::UnrecognizedCiphertextVersion(_)) => {
                SignalErrorCode::UnknownCiphertextVersion
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidMessage(..))
            | SignalFfiError::Signal(SignalProtocolError::CiphertextMessageTooShort(_))
            | SignalFfiError::Signal(SignalProtocolError::InvalidSealedSenderMessage(_))
            | SignalFfiError::Signal(SignalProtocolError::BadKEMCiphertextLength(_, _))
            | SignalFfiError::SignalCrypto(SignalCryptoError::InvalidTag)
            | SignalFfiError::Sgx(SgxError::DcapError(_))
            | SignalFfiError::Sgx(SgxError::NoiseError(_))
            | SignalFfiError::Sgx(SgxError::NoiseHandshakeError(_))
            | SignalFfiError::HsmEnclave(HsmEnclaveError::HSMHandshakeError(_))
            | SignalFfiError::HsmEnclave(HsmEnclaveError::HSMCommunicationError(_)) => {
                SignalErrorCode::InvalidMessage
            }

            SignalFfiError::Signal(SignalProtocolError::LegacyCiphertextVersion(_)) => {
                SignalErrorCode::LegacyCiphertextVersion
            }

            SignalFfiError::Signal(SignalProtocolError::UntrustedIdentity(_))
            | SignalFfiError::HsmEnclave(HsmEnclaveError::TrustedCodeError) => {
                SignalErrorCode::UntrustedIdentity
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidState(_, _))
            | SignalFfiError::Sgx(SgxError::InvalidBridgeStateError)
            | SignalFfiError::HsmEnclave(HsmEnclaveError::InvalidBridgeStateError) => {
                SignalErrorCode::InvalidState
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidSessionStructure(_)) => {
                SignalErrorCode::InvalidSession
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidSenderKeySession { .. }) => {
                SignalErrorCode::InvalidSenderKeySession
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidArgument(_))
            | SignalFfiError::HsmEnclave(HsmEnclaveError::InvalidCodeHashError)
            | SignalFfiError::SignalCrypto(_) => SignalErrorCode::InvalidArgument,

            SignalFfiError::Signal(SignalProtocolError::ApplicationCallbackError(_, _)) => {
                SignalErrorCode::CallbackError
            }

            SignalFfiError::ZkGroupVerificationFailure(ZkGroupVerificationFailure) => {
                SignalErrorCode::VerificationFailure
            }

            SignalFfiError::ZkGroupDeserializationFailure(ZkGroupDeserializationFailure) => {
                SignalErrorCode::InvalidType
            }

            SignalFfiError::UsernameError(UsernameError::CannotBeEmpty) => {
                SignalErrorCode::UsernameCannotBeEmpty
            }

            SignalFfiError::UsernameError(UsernameError::CannotStartWithDigit) => {
                SignalErrorCode::UsernameCannotStartWithDigit
            }

            SignalFfiError::UsernameError(UsernameError::MissingSeparator) => {
                SignalErrorCode::UsernameMissingSeparator
            }

            SignalFfiError::UsernameError(UsernameError::BadDiscriminator) => {
                SignalErrorCode::UsernameBadDiscriminator
            }

            SignalFfiError::UsernameError(UsernameError::BadNicknameCharacter) => {
                SignalErrorCode::UsernameBadCharacter
            }

            SignalFfiError::UsernameError(UsernameError::NicknameTooShort) => {
                SignalErrorCode::UsernameTooShort
            }

            SignalFfiError::UsernameError(UsernameError::NicknameTooLong)
            | SignalFfiError::UsernameLinkError(UsernameLinkError::InputDataTooLong) => {
                SignalErrorCode::UsernameTooLong
            }

            SignalFfiError::UsernameError(UsernameError::ProofVerificationFailure) => {
                SignalErrorCode::VerificationFailure
            }

            SignalFfiError::UsernameLinkError(UsernameLinkError::InvalidEntropyDataLength) => {
                SignalErrorCode::UsernameLinkInvalidEntropyDataLength
            }

            SignalFfiError::UsernameLinkError(_) => SignalErrorCode::UsernameLinkInvalid,

            SignalFfiError::Io(_) => SignalErrorCode::IoError,

            #[cfg(feature = "signal-media")]
            SignalFfiError::MediaSanitizeParse(err) => {
                use signal_media::sanitize::ParseError;
                match err.kind {
                    ParseError::InvalidBoxLayout { .. }
                    | ParseError::InvalidInput { .. }
                    | ParseError::MissingRequiredBox { .. }
                    | ParseError::TruncatedBox => SignalErrorCode::InvalidMediaInput,

                    ParseError::UnsupportedBoxLayout { .. }
                    | ParseError::UnsupportedBox { .. }
                    | ParseError::UnsupportedFormat { .. } => {
                        SignalErrorCode::UnsupportedMediaInput
                    }
                }
            }
        }
    }
}
