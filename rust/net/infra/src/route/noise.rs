//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::route::SimpleRoute;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NoiseRouteFragment<N> {
    pub handshake: N,
    pub initial_payload: Option<Box<[u8]>>,
}

pub type NoiseRoute<N, Inner> = SimpleRoute<NoiseRouteFragment<N>, Inner>;
