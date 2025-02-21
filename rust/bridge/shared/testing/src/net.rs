//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::str::FromStr;

use libsignal_bridge_macros::*;
use libsignal_bridge_types::net::chat::ServerMessageAck;
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_core::E164;
use libsignal_net::cdsi::{CdsiProtocolError, LookupError, LookupResponse, LookupResponseEntry};
use libsignal_net::chat::ChatServiceError;
use libsignal_net::infra::ws2::attested::AttestedProtocolError;
use libsignal_protocol::{Aci, Pni};
use nonzero_ext::nonzero;
use uuid::Uuid;

use crate::*;

pub mod chat;

#[bridge_io(TokioAsyncContext)]
async fn TESTING_CdsiLookupResponseConvert() -> LookupResponse {
    const E164_BOTH: E164 = E164::new(nonzero!(18005551011u64));
    const E164_PNI: E164 = E164::new(nonzero!(18005551012u64));
    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const PNI_UUID: &str = "796abedb-ca4e-4f18-8803-1fde5b921f9f";
    const DEBUG_PERMITS_USED: i32 = 123;

    let aci = Aci::from(Uuid::parse_str(ACI_UUID).expect("is valid"));
    let pni = Pni::from(Uuid::parse_str(PNI_UUID).expect("is valid"));

    LookupResponse {
        records: vec![
            LookupResponseEntry {
                e164: E164_BOTH,
                aci: Some(aci),
                pni: Some(pni),
            },
            LookupResponseEntry {
                e164: E164_PNI,
                pni: Some(pni),
                aci: None,
            },
        ],
        debug_permits_used: DEBUG_PERMITS_USED,
    }
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_OnlyCompletesByCancellation() {
    std::future::pending::<()>().await
}

macro_rules! make_error_testing_enum {
    (enum $name:ident for $orig:ident {
        $($orig_case:ident => $case:ident,)*
        $(; $($extra_case:ident,)*)?
    }) => {
        #[derive(Copy, Clone, strum::EnumString)]
        enum $name {
            $($case,)*
            $($($extra_case,)*)?
        }
        const _: () = {
            /// This code isn't ever executed. It exists so that when new cases are
            /// added to the original enum, this will fail to compile until corresponding
            /// cases are added to the testing enum.
            #[allow(unused)]
            fn match_on_lookup_error(value: &'static $orig) -> $name {
                match value {
                    $($orig::$orig_case { .. } => $name::$case),*
                }
            }
        };
        impl TryFrom<String> for $name {
            type Error = <Self as FromStr>::Err;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                FromStr::from_str(&value)
            }
        }
    }
}

make_error_testing_enum! {
    enum TestingCdsiLookupError for LookupError {
        EnclaveProtocol => Protocol,
        CdsiProtocol => CdsiProtocol,
        AttestationError => AttestationDataError,
        InvalidResponse => InvalidResponse,
        RateLimited => RetryAfter42Seconds,
        InvalidToken => InvalidToken,
        InvalidArgument => InvalidArgument,
        ParseError => Parse,
        ConnectTransport => ConnectDnsFailed,
        WebSocket => WebSocketIdleTooLong,
        ConnectionTimedOut => ConnectionTimedOut,
        Server => ServerCrashed,
    }
}

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_CdsiLookupErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingCdsiLookupError, String>,
) -> Result<(), LookupError> {
    Err(match error_description.into_inner() {
        TestingCdsiLookupError::Protocol => {
            LookupError::EnclaveProtocol(AttestedProtocolError::ProtobufDecode)
        }
        TestingCdsiLookupError::CdsiProtocol => {
            LookupError::CdsiProtocol(CdsiProtocolError::NoTokenInResponse)
        }
        TestingCdsiLookupError::AttestationDataError => {
            LookupError::AttestationError(attest::enclave::Error::AttestationDataError {
                reason: "fake reason".into(),
            })
        }
        TestingCdsiLookupError::InvalidResponse => LookupError::InvalidResponse,
        TestingCdsiLookupError::RetryAfter42Seconds => LookupError::RateLimited {
            retry_after_seconds: 42,
        },
        TestingCdsiLookupError::InvalidToken => LookupError::InvalidToken,
        TestingCdsiLookupError::InvalidArgument => LookupError::InvalidArgument {
            server_reason: "fake reason".into(),
        },
        TestingCdsiLookupError::Parse => LookupError::ParseError,
        TestingCdsiLookupError::ConnectDnsFailed => LookupError::ConnectTransport(
            libsignal_net::infra::errors::TransportConnectError::DnsError,
        ),
        TestingCdsiLookupError::WebSocketIdleTooLong => LookupError::WebSocket(
            libsignal_net::infra::ws::WebSocketServiceError::ChannelIdleTooLong,
        ),
        TestingCdsiLookupError::ConnectionTimedOut => LookupError::ConnectionTimedOut,
        TestingCdsiLookupError::ServerCrashed => LookupError::Server { reason: "crashed" },
    })
}

make_error_testing_enum! {
    enum TestingChatServiceError for ChatServiceError {
        WebSocket => WebSocket,
        AppExpired => AppExpired,
        DeviceDeregistered => DeviceDeregistered,
        UnexpectedFrameReceived => UnexpectedFrameReceived,
        ServerRequestMissingId => ServerRequestMissingId,
        IncomingDataInvalid => IncomingDataInvalid,
        RequestHasInvalidHeader => RequestHasInvalidHeader,
        RequestSendTimedOut => RequestSendTimedOut,
        TimeoutEstablishingConnection => TimeoutEstablishingConnection,
        AllConnectionRoutesFailed => AllConnectionRoutesFailed,
        InvalidConnectionConfiguration => InvalidConnectionConfiguration,
        Disconnected => Disconnected,
        RetryLater => RetryAfter42Seconds,
    }
}

#[bridge_fn]
fn TESTING_ChatServiceErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingChatServiceError, String>,
) -> Result<(), ChatServiceError> {
    Err(match error_description.into_inner() {
        TestingChatServiceError::WebSocket => ChatServiceError::WebSocket(
            libsignal_net::infra::ws::WebSocketServiceError::Other("testing"),
        ),
        TestingChatServiceError::AppExpired => ChatServiceError::AppExpired,
        TestingChatServiceError::DeviceDeregistered => ChatServiceError::DeviceDeregistered,
        TestingChatServiceError::UnexpectedFrameReceived => {
            ChatServiceError::UnexpectedFrameReceived
        }
        TestingChatServiceError::ServerRequestMissingId => ChatServiceError::ServerRequestMissingId,
        TestingChatServiceError::IncomingDataInvalid => ChatServiceError::IncomingDataInvalid,
        TestingChatServiceError::RequestHasInvalidHeader => {
            ChatServiceError::RequestHasInvalidHeader
        }
        TestingChatServiceError::RequestSendTimedOut => ChatServiceError::RequestSendTimedOut,
        TestingChatServiceError::TimeoutEstablishingConnection => {
            ChatServiceError::TimeoutEstablishingConnection
        }
        TestingChatServiceError::AllConnectionRoutesFailed => {
            ChatServiceError::AllConnectionRoutesFailed
        }
        TestingChatServiceError::InvalidConnectionConfiguration => {
            ChatServiceError::InvalidConnectionConfiguration
        }
        TestingChatServiceError::Disconnected => ChatServiceError::Disconnected,
        TestingChatServiceError::RetryAfter42Seconds => ChatServiceError::RetryLater {
            retry_after_seconds: 42,
        },
    })
}

#[bridge_fn(jni = false, ffi = false)]
fn TESTING_ServerMessageAck_Create() -> ServerMessageAck {
    ServerMessageAck::new(Box::new(|_| Ok(())))
}

#[bridge_fn(jni = false, ffi = false)]
fn TESTING_ConnectionManager_newLocalOverride(
    userAgent: String,
    chatPort: AsType<NonZeroU16, u16>,
    cdsiPort: AsType<NonZeroU16, u16>,
    svr2Port: AsType<NonZeroU16, u16>,
    svr3SgxPort: AsType<NonZeroU16, u16>,
    svr3NitroPort: AsType<NonZeroU16, u16>,
    svr3Tpm2SnpPort: AsType<NonZeroU16, u16>,
    rootCertificateDer: &[u8],
) -> ConnectionManager {
    let ports = net_env::LocalhostEnvPortConfig {
        chat_port: chatPort.into_inner(),
        cdsi_port: cdsiPort.into_inner(),
        svr2_port: svr2Port.into_inner(),
        svr3_sgx_port: svr3SgxPort.into_inner(),
        svr3_nitro_port: svr3NitroPort.into_inner(),
        svr3_tpm2_snp_port: svr3Tpm2SnpPort.into_inner(),
    };

    let env = net_env::localhost_test_env_with_ports(ports, rootCertificateDer);
    ConnectionManager::new_from_static_environment(env, userAgent.as_str())
}

#[bridge_fn]
fn TESTING_ConnectionManager_isUsingProxy(manager: &ConnectionManager) -> i32 {
    match manager.is_using_proxy() {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}
