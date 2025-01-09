//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::route::{RouteProvider, RouteProviderContext};

/// Additional methods available for [`RouteProvider`]s.
///
/// Provides utility combinators for `RouteProvider`s, similar to
/// [`std::iter::Iterator`].
pub trait RouteProviderExt: RouteProvider + Sized {
    /// Returns a new [`RouteProvider`] that transforms routes.
    ///
    /// Consumes an existing route provider and returns a new one that returns
    /// the result of invoking the provided callback on each route produced by
    /// the original provider.
    ///
    /// This is analagous to [`Iterator::map`] for iterators.
    fn map_routes<F: Fn(Self::Route) -> T, T>(self, f: F) -> Map<Self, F> {
        Map(self, f)
    }

    /// Returns a new [`RouteProvider`] that filters routes.
    ///
    /// Consumes an existing route provider and returns a new one that filters
    /// the output of the original by only returning routes for which the
    /// provided callback returns `true`.
    ///
    /// This is analagous to [`Iterator::filter`] for iterators.
    fn filter_routes<F: Fn(&Self::Route) -> bool>(self, f: F) -> Filter<Self, F> {
        Filter(self, f)
    }
}

impl<R: RouteProvider> RouteProviderExt for R {}

/// The [`RouteProvider`] returned by [`RouteProviderExt::map_routes`].
pub struct Map<R, F>(R, F);

impl<R: RouteProvider, F: Fn(R::Route) -> T, T> RouteProvider for Map<R, F> {
    type Route = T;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        self.0.routes(context).map(&self.1)
    }
}

/// The [`RouteProvider`] returned by [`RouteProviderExt::filter_routes`].
pub struct Filter<R, F>(R, F);

impl<R: RouteProvider, F: Fn(&R::Route) -> bool> RouteProvider for Filter<R, F> {
    type Route = R::Route;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        self.0.routes(context).filter(&self.1)
    }
}
