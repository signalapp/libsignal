//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;

use crate::dns::dns_message;
use crate::dns::dns_message::MAX_DNS_UDP_MESSAGE_LEN;

#[derive(displaydoc::Display, Debug, thiserror::Error, Clone)]
pub enum Error {
    /// DNS lookup failed
    LookupFailed,
    /// DNS lookup timed out
    Timeout,
    /// DNS lookup on cooldown
    Cooldown,
    /// Internal IO error
    Io(io::ErrorKind),
    /// Received a response with a message ID that doesn't match any of the requests sent
    UnexpectedMessageId,
    /// Data for the given name is not available
    NoData,
    /// Failed to connect over the specific transport
    TransportFailure,
    /// A UDP message is longer than {MAX_DNS_UDP_MESSAGE_LEN:?} octets
    MessageTooLong,
    /// DoH request resulted in a non-200 response code: {0}
    DohRequestBadStatus(u16),
    /// Specific IP requested but only other type available
    RequestedIpTypeNotFound,
    /// Failed to create transport due to restrictions
    TransportRestricted,
    /// Protocol error: {0}
    Protocol(dns_message::Error),
    /// DNS request resulted in a non-zero error code: {0}
    RequestFailedWithErrorCode(u8),
}

impl From<dns_message::Error> for Error {
    fn from(error: dns_message::Error) -> Self {
        match error {
            dns_message::Error::ProtocolErrorLabelTooLong
            | dns_message::Error::ProtocolErrorLabelEmpty
            | dns_message::Error::ProtocolErrorNameTooLong
            | dns_message::Error::ProtocolErrorUnexpectedValue
            | dns_message::Error::ProtocolErrorInvalidNameCharacters
            | dns_message::Error::ProtocolErrorFailedToParseResourceRecord
            | dns_message::Error::ProtocolErrorInvalidMessage => Error::Protocol(error),
            dns_message::Error::NoData => Error::NoData,
            dns_message::Error::RequestFailedWithErrorCode(code) => {
                Error::RequestFailedWithErrorCode(code)
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(a: io::Error) -> Self {
        Error::Io(a.kind())
    }
}
