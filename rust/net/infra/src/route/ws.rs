//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::hash::Hash;

use http::uri::PathAndQuery;
use http::HeaderMap;
use tungstenite::protocol::WebSocketConfig;

use crate::route::{ReplaceFragment, RouteProvider, RouteProviderContext, SimpleRoute};

#[derive(Clone, Debug)]
pub struct WebSocketRouteFragment {
    /// Protocol-level configuration.
    pub ws_config: WebSocketConfig,
    /// The HTTP path to use when establishing the websocket connection.
    pub endpoint: PathAndQuery,
    /// Request headers to include in the HTTP request establishing the connection.
    pub headers: HeaderMap,
}

impl AsMut<WebSocketRouteFragment> for WebSocketRouteFragment {
    fn as_mut(&mut self) -> &mut WebSocketRouteFragment {
        self
    }
}

pub type WebSocketRoute<H> = SimpleRoute<WebSocketRouteFragment, H>;

#[derive(Debug)]
pub struct WebSocketProvider<P> {
    pub(crate) fragment: WebSocketRouteFragment,
    pub(crate) inner: P,
}

impl<P> WebSocketProvider<P> {
    pub fn new(fragment: WebSocketRouteFragment, inner: P) -> Self {
        Self { fragment, inner }
    }
}

impl<P: RouteProvider> RouteProvider for WebSocketProvider<P> {
    type Route = WebSocketRoute<P::Route>;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        self.inner.routes(context).map(|route| WebSocketRoute {
            inner: route,
            fragment: self.fragment.clone(),
        })
    }
}

impl<R: ReplaceFragment<S>, S> ReplaceFragment<S> for WebSocketRoute<R> {
    type Replacement<T> = WebSocketRoute<R::Replacement<T>>;

    fn replace<T>(self, make_fragment: impl FnOnce(S) -> T) -> Self::Replacement<T> {
        let Self { inner, fragment } = self;
        WebSocketRoute {
            inner: inner.replace(make_fragment),
            fragment,
        }
    }
}

/// Manual impl because [`tungstenite::protocol::WebSocketConfig`] doesn't
/// implement [`PartialEq`].
impl PartialEq for WebSocketRouteFragment {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            ws_config,
            endpoint,
            headers,
        } = self;
        endpoint == &other.endpoint
            && headers == &other.headers
            && ws_config_eq(ws_config, &other.ws_config)
    }
}

impl Eq for WebSocketRouteFragment {}

impl std::hash::Hash for WebSocketRouteFragment {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let Self {
            ws_config,
            endpoint,
            headers: _,
        } = self;
        ws_config_hash(ws_config, state);
        endpoint.hash(state);
    }
}

#[allow(deprecated)]
fn ws_config_eq(lhs: &WebSocketConfig, rhs: &WebSocketConfig) -> bool {
    let WebSocketConfig {
        max_send_queue,
        write_buffer_size,
        max_write_buffer_size,
        max_message_size,
        max_frame_size,
        accept_unmasked_frames,
    } = lhs;

    max_send_queue == &rhs.max_send_queue
        && write_buffer_size == &rhs.write_buffer_size
        && max_write_buffer_size == &rhs.max_write_buffer_size
        && max_message_size == &rhs.max_message_size
        && max_frame_size == &rhs.max_frame_size
        && accept_unmasked_frames == &rhs.accept_unmasked_frames
}

#[allow(deprecated)]
fn ws_config_hash(ws: &WebSocketConfig, state: &mut impl std::hash::Hasher) {
    let WebSocketConfig {
        max_send_queue,
        write_buffer_size,
        max_write_buffer_size,
        max_message_size,
        max_frame_size,
        accept_unmasked_frames,
    } = ws;

    max_send_queue.hash(state);
    write_buffer_size.hash(state);
    max_write_buffer_size.hash(state);
    max_message_size.hash(state);
    max_frame_size.hash(state);
    accept_unmasked_frames.hash(state);
}
