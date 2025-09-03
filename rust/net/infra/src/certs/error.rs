//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use itertools::Itertools as _;
use rustls::pki_types::UnixTime;
use rustls::{
    AlertDescription, CertRevocationListError, CertificateError, EncryptedClientHelloError, Error,
    InconsistentKeys, InvalidMessage, PeerIncompatible, PeerMisbehaved,
};

use crate::dns::dns_utils::log_safe_domain;
use crate::errors::LogSafeDisplay;

pub(super) struct LogSafeTlsError<'a>(pub(super) &'a Error);

impl LogSafeDisplay for LogSafeTlsError<'_> {}
impl std::fmt::Display for LogSafeTlsError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Match all possible error variations to provide alternate formatting
        // for ones that might contain sensitive user data. If the match arm for
        // a case doesn't exit early, the Display impl will be used for it.

        // The goal of the below is to show that our choices of what to allow
        // the default formatter for are safe. Naming the types of values shows
        // that they don't contain sensitive data and makes sure that if they
        // change in a future crate update (to types that might contain user
        // data), this code will stop compiling.
        match self.0 {
            Error::NoCertificatesPresented
            | Error::UnsupportedNameType
            | Error::DecryptError
            | Error::EncryptError
            | Error::FailedToGetCurrentTime
            | Error::FailedToGetRandomBytes
            | Error::HandshakeNotComplete
            | Error::PeerSentOversizedRecord
            | Error::NoApplicationProtocol
            | Error::BadMaxFragmentSize => (),
            Error::InappropriateMessage {
                expect_types,
                got_type,
            } => {
                let _: &Vec<rustls::ContentType> = expect_types;
                let _: &rustls::ContentType = got_type;
            }
            Error::InappropriateHandshakeMessage {
                expect_types,
                got_type,
            } => {
                let _: &Vec<rustls::HandshakeType> = expect_types;
                let _: &rustls::HandshakeType = got_type;
            }
            Error::InvalidEncryptedClientHello(invalid_ech) => {
                match invalid_ech {
                    EncryptedClientHelloError::InvalidConfigList
                    | EncryptedClientHelloError::NoCompatibleConfig
                    | EncryptedClientHelloError::SniRequired => (),
                    // This enum is non-exhaustive.
                    _ => return f.write_str("invalid ECH, unknown reason"),
                }
            }
            Error::InvalidMessage(invalid_message) => match invalid_message {
                InvalidMessage::CertificatePayloadTooLarge
                | InvalidMessage::HandshakePayloadTooLarge
                | InvalidMessage::InvalidCcs
                | InvalidMessage::InvalidContentType
                | InvalidMessage::InvalidCertificateStatusType
                | InvalidMessage::InvalidCertRequest
                | InvalidMessage::InvalidDhParams
                | InvalidMessage::InvalidEmptyPayload
                | InvalidMessage::InvalidKeyUpdate
                | InvalidMessage::InvalidServerName
                | InvalidMessage::MessageTooLarge
                | InvalidMessage::MessageTooShort
                | InvalidMessage::MissingKeyExchange
                | InvalidMessage::NoSignatureSchemes
                | InvalidMessage::UnknownProtocolVersion
                | InvalidMessage::UnsupportedCompression
                | InvalidMessage::UnsupportedCurveType => (),
                InvalidMessage::MissingData(s)
                | InvalidMessage::TrailingData(s)
                | InvalidMessage::UnexpectedMessage(s) => {
                    let _: &'static str = s;
                }
                InvalidMessage::UnsupportedKeyExchangeAlgorithm(alg) => {
                    match alg {
                        rustls::crypto::KeyExchangeAlgorithm::DHE
                        | rustls::crypto::KeyExchangeAlgorithm::ECDHE => (),
                        // This enum is non-exhaustive.
                        _ => return f.write_str("invalid message, unknown key exchange algorithm"),
                    }
                }
                // This enum is non-exhaustive.
                _ => return f.write_str("invalid message, unknown reason"),
            },
            Error::PeerIncompatible(peer_incompatible) => match peer_incompatible {
                PeerIncompatible::EcPointsExtensionRequired
                | PeerIncompatible::ExtendedMasterSecretExtensionRequired
                | PeerIncompatible::IncorrectCertificateTypeExtension
                | PeerIncompatible::KeyShareExtensionRequired
                | PeerIncompatible::NamedGroupsExtensionRequired
                | PeerIncompatible::NoCertificateRequestSignatureSchemesInCommon
                | PeerIncompatible::NoCipherSuitesInCommon
                | PeerIncompatible::NoEcPointFormatsInCommon
                | PeerIncompatible::NoKxGroupsInCommon
                | PeerIncompatible::NoSignatureSchemesInCommon
                | PeerIncompatible::NullCompressionRequired
                | PeerIncompatible::ServerDoesNotSupportTls12Or13
                | PeerIncompatible::ServerSentHelloRetryRequestWithUnknownExtension
                | PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
                | PeerIncompatible::SignatureAlgorithmsExtensionRequired
                | PeerIncompatible::SupportedVersionsExtensionRequired
                | PeerIncompatible::Tls12NotOffered
                | PeerIncompatible::Tls12NotOfferedOrEnabled
                | PeerIncompatible::Tls13RequiredForQuic
                | PeerIncompatible::UncompressedEcPointsRequired
                | PeerIncompatible::UnsolicitedCertificateTypeExtension => (),
                PeerIncompatible::ServerRejectedEncryptedClientHello(_ech_config_payloads) => {
                    return f.write_str("peer incompatible, server rejected ECH");
                }
                // This enum is non-exhaustive
                _ => return f.write_str("peer incompatible, unknown reason"),
            },
            Error::PeerMisbehaved(peer_misbehaved) => match peer_misbehaved {
                PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported
                | PeerMisbehaved::BadCertChainExtensions
                | PeerMisbehaved::DisallowedEncryptedExtension
                | PeerMisbehaved::DuplicateClientHelloExtensions
                | PeerMisbehaved::DuplicateEncryptedExtensions
                | PeerMisbehaved::DuplicateHelloRetryRequestExtensions
                | PeerMisbehaved::DuplicateNewSessionTicketExtensions
                | PeerMisbehaved::DuplicateServerHelloExtensions
                | PeerMisbehaved::DuplicateServerNameTypes
                | PeerMisbehaved::EarlyDataAttemptedInSecondClientHello
                | PeerMisbehaved::EarlyDataExtensionWithoutResumption
                | PeerMisbehaved::EarlyDataOfferedWithVariedCipherSuite
                | PeerMisbehaved::HandshakeHashVariedAfterRetry
                | PeerMisbehaved::IllegalHelloRetryRequestWithEmptyCookie
                | PeerMisbehaved::IllegalHelloRetryRequestWithNoChanges
                | PeerMisbehaved::IllegalHelloRetryRequestWithOfferedGroup
                | PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedCipherSuite
                | PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup
                | PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion
                | PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId
                | PeerMisbehaved::IllegalHelloRetryRequestWithInvalidEch
                | PeerMisbehaved::IllegalMiddleboxChangeCipherSpec
                | PeerMisbehaved::IllegalTlsInnerPlaintext
                | PeerMisbehaved::IncorrectBinder
                | PeerMisbehaved::InvalidCertCompression
                | PeerMisbehaved::InvalidMaxEarlyDataSize
                | PeerMisbehaved::InvalidKeyShare
                | PeerMisbehaved::KeyEpochWithPendingFragment
                | PeerMisbehaved::KeyUpdateReceivedInQuicConnection
                | PeerMisbehaved::MessageInterleavedWithHandshakeMessage
                | PeerMisbehaved::MissingBinderInPskExtension
                | PeerMisbehaved::MissingKeyShare
                | PeerMisbehaved::MissingPskModesExtension
                | PeerMisbehaved::MissingQuicTransportParameters
                | PeerMisbehaved::OfferedDuplicateCertificateCompressions
                | PeerMisbehaved::OfferedDuplicateKeyShares
                | PeerMisbehaved::OfferedEarlyDataWithOldProtocolVersion
                | PeerMisbehaved::OfferedEmptyApplicationProtocol
                | PeerMisbehaved::OfferedIncorrectCompressions
                | PeerMisbehaved::PskExtensionMustBeLast
                | PeerMisbehaved::PskExtensionWithMismatchedIdsAndBinders
                | PeerMisbehaved::RefusedToFollowHelloRetryRequest
                | PeerMisbehaved::RejectedEarlyDataInterleavedWithHandshakeMessage
                | PeerMisbehaved::ResumptionAttemptedWithVariedEms
                | PeerMisbehaved::ResumptionOfferedWithVariedCipherSuite
                | PeerMisbehaved::ResumptionOfferedWithVariedEms
                | PeerMisbehaved::ResumptionOfferedWithIncompatibleCipherSuite
                | PeerMisbehaved::SelectedDifferentCipherSuiteAfterRetry
                | PeerMisbehaved::SelectedInvalidPsk
                | PeerMisbehaved::SelectedTls12UsingTls13VersionExtension
                | PeerMisbehaved::SelectedUnofferedApplicationProtocol
                | PeerMisbehaved::SelectedUnofferedCertCompression
                | PeerMisbehaved::SelectedUnofferedCipherSuite
                | PeerMisbehaved::SelectedUnofferedCompression
                | PeerMisbehaved::SelectedUnofferedKxGroup
                | PeerMisbehaved::SelectedUnofferedPsk
                | PeerMisbehaved::SelectedUnusableCipherSuiteForVersion
                | PeerMisbehaved::ServerEchoedCompatibilitySessionId
                | PeerMisbehaved::ServerHelloMustOfferUncompressedEcPoints
                | PeerMisbehaved::ServerNameDifferedOnRetry
                | PeerMisbehaved::ServerNameMustContainOneHostName
                | PeerMisbehaved::SignedKxWithWrongAlgorithm
                | PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme
                | PeerMisbehaved::TooManyEmptyFragments
                | PeerMisbehaved::TooManyKeyUpdateRequests
                | PeerMisbehaved::TooManyRenegotiationRequests
                | PeerMisbehaved::TooManyWarningAlertsReceived
                | PeerMisbehaved::TooMuchEarlyDataReceived
                | PeerMisbehaved::UnexpectedCleartextExtension
                | PeerMisbehaved::UnsolicitedCertExtension
                | PeerMisbehaved::UnsolicitedEncryptedExtension
                | PeerMisbehaved::UnsolicitedSctList
                | PeerMisbehaved::UnsolicitedServerHelloExtension
                | PeerMisbehaved::WrongGroupForKeyShare
                | PeerMisbehaved::UnsolicitedEchExtension => (),
                // This enum is non-exhaustive.
                _ => return f.write_str("peer misbehaved, unknown reason"),
            },
            Error::AlertReceived(alert_description) => match alert_description {
                AlertDescription::CloseNotify
                | AlertDescription::UnexpectedMessage
                | AlertDescription::BadRecordMac
                | AlertDescription::DecryptionFailed
                | AlertDescription::RecordOverflow
                | AlertDescription::DecompressionFailure
                | AlertDescription::HandshakeFailure
                | AlertDescription::NoCertificate
                | AlertDescription::BadCertificate
                | AlertDescription::UnsupportedCertificate
                | AlertDescription::CertificateRevoked
                | AlertDescription::CertificateExpired
                | AlertDescription::CertificateUnknown
                | AlertDescription::IllegalParameter
                | AlertDescription::UnknownCA
                | AlertDescription::AccessDenied
                | AlertDescription::DecodeError
                | AlertDescription::DecryptError
                | AlertDescription::ExportRestriction
                | AlertDescription::ProtocolVersion
                | AlertDescription::InsufficientSecurity
                | AlertDescription::InternalError
                | AlertDescription::InappropriateFallback
                | AlertDescription::UserCanceled
                | AlertDescription::NoRenegotiation
                | AlertDescription::MissingExtension
                | AlertDescription::UnsupportedExtension
                | AlertDescription::CertificateUnobtainable
                | AlertDescription::UnrecognisedName
                | AlertDescription::BadCertificateStatusResponse
                | AlertDescription::BadCertificateHashValue
                | AlertDescription::UnknownPSKIdentity
                | AlertDescription::CertificateRequired
                | AlertDescription::NoApplicationProtocol
                | AlertDescription::EncryptedClientHelloRequired => (),
                AlertDescription::Unknown(reason) => {
                    let _: &u8 = reason;
                }
                // This enum is non-exhaustive
                _ => return f.write_str("alert received, unknown description"),
            },
            Error::InvalidCertificate(certificate_error) => match certificate_error {
                CertificateError::BadEncoding
                | CertificateError::Expired
                | CertificateError::NotValidYet
                | CertificateError::Revoked
                | CertificateError::UnhandledCriticalExtension
                | CertificateError::UnknownIssuer
                | CertificateError::UnknownRevocationStatus
                | CertificateError::BadSignature
                | CertificateError::NotValidForName
                | CertificateError::InvalidPurpose
                | CertificateError::ApplicationVerificationFailure
                | CertificateError::ExpiredRevocationList => (),
                CertificateError::ExpiredContext { time, not_after } => {
                    let _: [&UnixTime; 2] = [time, not_after];
                }
                CertificateError::NotValidYetContext { time, not_before } => {
                    let _: [&UnixTime; 2] = [time, not_before];
                }
                CertificateError::ExpiredRevocationListContext { time, next_update } => {
                    let _: [&UnixTime; 2] = [time, next_update];
                }
                CertificateError::NotValidForNameContext {
                    expected,
                    presented,
                } => {
                    return write!(
                        f,
                        "invalid certificate; expected {} is not in presented {:?}",
                        log_safe_domain(&expected.to_str()),
                        presented.iter().map(|s| log_safe_domain(s)).collect_vec()
                    );
                }
                CertificateError::Other(_other_error) => {
                    return f.write_str("invalid certificate, other error");
                }
                // This enum is non-exhaustive
                _ => return f.write_str("invalid certificate, unknown error"),
            },
            Error::InvalidCertRevocationList(crl_error) => match crl_error {
                CertRevocationListError::BadSignature
                | CertRevocationListError::InvalidCrlNumber
                | CertRevocationListError::InvalidRevokedCertSerialNumber
                | CertRevocationListError::IssuerInvalidForCrl
                | CertRevocationListError::ParseError
                | CertRevocationListError::UnsupportedCrlVersion
                | CertRevocationListError::UnsupportedCriticalExtension
                | CertRevocationListError::UnsupportedDeltaCrl
                | CertRevocationListError::UnsupportedIndirectCrl
                | CertRevocationListError::UnsupportedRevocationReason => (),
                CertRevocationListError::Other(_other_error) => {
                    return f.write_str("invalid CRL, other error");
                }
                // This enum is non-exhaustive
                _ => return f.write_str("invalid CRL, unknown error"),
            },
            Error::InconsistentKeys(inconsistent_keys) => match inconsistent_keys {
                InconsistentKeys::KeyMismatch | InconsistentKeys::Unknown => (),
                // This enum is non-exhaustive
                _ => return f.write_str("inconsistent keys, unknown error"),
            },
            Error::General(_reason) => return f.write_str("general error"),
            Error::Other(_other_error) => return f.write_str("other error"),
            // This enum is non-exhaustive
            _ => return f.write_str("unknown error"),
        };
        self.0.fmt(f)
    }
}
