//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::net::IpAddr;

use libsignal_core::try_scoped;
use libsignal_net_infra::noise::{
    EPHEMERAL_KEY_LEN, HandshakeAuthKind, NoiseHandshake, STATIC_KEY_LEN,
};
use libsignal_net_infra::route::{
    ComposedConnector, Connector, ResolveHostnames, ResolvedRoute, UnresolvedHost,
};

mod encrypted_stream;
pub use encrypted_stream::{
    Authorization, ChatNoiseConnector, ConnectError, ConnectMeta, ServerPublicKey,
};

pub type ChatNoiseFragment = (Authorization, ConnectMeta);

#[derive(Clone, Debug, PartialEq)]
pub struct ChatNoiseRoute<T> {
    pub fragment: ChatNoiseFragment,
    pub inner: T,
}

const STATIC_KEY_AEAD_TAG_LEN: usize = 16;

#[derive(Clone)]
pub enum HandshakeAuth<'k> {
    IK {
        server_public_key: &'k [u8; STATIC_KEY_LEN],
        client_private_key: &'k [u8; EPHEMERAL_KEY_LEN],
    },
    NK {
        server_public_key: &'k [u8; STATIC_KEY_LEN],
    },
}

impl NoiseHandshake for HandshakeAuth<'_> {
    fn handshake_message_len(&self) -> usize {
        match self {
            Self::IK { .. } => EPHEMERAL_KEY_LEN + STATIC_KEY_LEN + STATIC_KEY_AEAD_TAG_LEN,
            Self::NK { .. } => EPHEMERAL_KEY_LEN,
        }
    }
    fn into_handshake_state(self) -> snow::HandshakeState {
        let resolver = Box::new(attest::snow_resolver::Resolver);
        try_scoped(|| {
            match self {
                HandshakeAuth::IK {
                    server_public_key,
                    client_private_key,
                } => snow::Builder::with_resolver(IK_NOISE_PATTERN.parse().unwrap(), resolver)
                    .remote_public_key(server_public_key)?
                    .local_private_key(client_private_key)?,
                HandshakeAuth::NK { server_public_key } => {
                    snow::Builder::with_resolver(NK_NOISE_PATTERN.parse().unwrap(), resolver)
                        .remote_public_key(server_public_key)?
                }
            }
            .build_initiator()
        })
        .expect("building handshake failed")
    }
    fn auth_kind(&self) -> HandshakeAuthKind {
        match self {
            HandshakeAuth::IK { .. } => HandshakeAuthKind::IK,
            HandshakeAuth::NK { .. } => HandshakeAuthKind::NK,
        }
    }
}

pub(crate) const IK_NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
pub(crate) const NK_NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2b";

impl<T: ResolveHostnames> ResolveHostnames for ChatNoiseRoute<T> {
    type Resolved = ChatNoiseRoute<T::Resolved>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        self.inner.hostnames()
    }

    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        let Self { inner, fragment } = self;
        ChatNoiseRoute {
            fragment,
            inner: inner.resolve(lookup),
        }
    }
}

impl<T: ResolvedRoute> ResolvedRoute for ChatNoiseRoute<T> {
    fn immediate_target(&self) -> &IpAddr {
        self.inner.immediate_target()
    }
}

impl<A, B, Inner, T, Error> Connector<ChatNoiseRoute<T>, Inner> for ComposedConnector<A, B, Error>
where
    A: Connector<ChatNoiseFragment, B::Connection, Error: Into<Error>> + Sync,
    B: Connector<T, Inner, Error: Into<Error>> + Sync,
    Inner: Send,
    T: Send,
{
    type Connection = A::Connection;

    type Error = Error;

    fn connect_over(
        &self,
        over: Inner,
        route: ChatNoiseRoute<T>,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let ChatNoiseRoute { fragment, inner } = route;
        self.connect_inner_then_outer(over, inner, fragment, log_tag)
    }
}
