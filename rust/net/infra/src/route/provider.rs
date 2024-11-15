//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::route::RouteProvider;

pub trait RouteProviderExt: RouteProvider + Sized {
    fn map_routes<F: Fn(Self::Route) -> T, T>(self, f: F) -> Map<Self, F> {
        Map(self, f)
    }
}

impl<R: RouteProvider> RouteProviderExt for R {}

pub struct Map<R, F>(R, F);

impl<R: RouteProvider, F: Fn(R::Route) -> T, T> RouteProvider for Map<R, F> {
    type Route = T;

    fn routes(&self) -> impl Iterator<Item = Self::Route> + '_ {
        self.0.routes().map(&self.1)
    }
}
