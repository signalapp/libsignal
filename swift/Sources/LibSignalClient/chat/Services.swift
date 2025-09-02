//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// A helper type used to select a particular \*Service protocol (like ``UnauthUsernamesService``)
/// from ``UnauthenticatedChatConnection``.
///
/// Expected usage:
///
/// ```swift
/// func accessService<Service: UnauthServiceSelector>(
///     _ chatConnection: UnauthenticatedChatConnection,
///     as serviceSelector: Service,
/// ) -> Service.Api {
///     // Have to force-cast here, unfortunately.
///     chatConnection as! Service.Api
/// }
/// ```
///
/// ```swift
/// accessService(chatConnection, as: .usernames)
/// ```
///
/// ## Explanation
///
/// What we'd *like* to write is something like
///
/// ```swift
/// func accessService<ServiceApi>(
///     _ chatConnection: UnauthenticatedChatConnection,
///     as service: ServiceApi.Type,
/// ) -> any ServiceApi where UnauthenticatedChatConnection: ServiceApi
/// ```
/// ```swift
/// accessService(chatConnection, as: UnauthUsernamesService.self)
/// ```
///
/// However, Swift doesn't support that kind of `where` clause, where the generic parameter
/// represents a protocol *and* the set of valid choices is limited based on which protocols a type
/// implements.
///
/// Our next try might look something like this:
///
/// ```swift
/// func accessService<ServiceApi: UnauthServiceBase>(
///     _ chatConnection: UnauthenticatedChatConnection,
///     as service: ServiceApi.Type,
/// ) -> any ServiceApi
/// ```
/// ```swift
/// accessService(chatConnection, as: UnauthUsernamesService.self)
/// ```
///
/// This loses the connection between `ServiceApi` and `UnauthenticatedChatConnection`, so the
/// implementation will have to do a force-cast, but that's okay; we still have static checking
/// through the presence of the "Base" protocol. But alas, this also fails, because
/// `ServiceApi: UnauthServiceBase` doesn't mean "ServiceApi inherits from UnauthServiceBase" in
/// this context; it means "the concrete type used for ServiceApi is a valid UnauthServiceBase". And
/// the concrete type is `any UnauthUsernamesService`, and unfortunately `any` types don't conform
/// to their own protocol in Swift, except for a few special cases. (This is a complicated sentence,
/// the details of which don't really matter here; if you aren't already familiar with this, just
/// think of it as `any` types not being "concrete enough" to count.)
///
/// So, failing this, we instead move to some kind of marker type:
///
/// ```swift
/// func accessService<Service: UnauthServiceSelector>(
///     _ chatConnection: UnauthenticatedChatConnection,
///     as service: Service.Type,
/// ) -> Service.Api
/// ```
/// ```swift
/// enum UnauthUsernamesServiceMarker: UnauthServiceSelector {
///     typealias Api = any UnauthUsernamesService
/// }
/// ```
/// ```swift
/// accessService(chatConnection, as: UnauthUsernamesServiceMarker.self)
/// ```
///
/// This works! It's a bit wordy, in that we have to define a new Marker type for every protocol,
/// but now we've separated "is a known unauth service" from "the type that actually represents the
/// service", and that gives us more flexibility. Now we just want to see if we can make it more
/// convenient to use.
///
/// We can pick up a technique originally added for SwiftUI: static member lookup in generic
/// contexts ([SE-0299][]). This lets us put members on the protocol that can be accessed through
/// `.member` shorthand (most commonly seen with enum cases)---basically "factory methods" for the
/// concrete implementors of a protocol.
///
/// ```swift
/// extension UnauthServiceSelector where Self == UnauthUsernamesServiceMarker {
///     static var usernames: Self.Type { UnauthUsernamesServiceMarker.self }
/// }
/// ```
/// ```swift
/// accessService(chatConnection, as: .usernames)
/// ```
///
/// Alas, context-based type inference doesn't kick in in this case. We need to actually produce a
/// value with type `Self`, not just a related type. But that's okay; we can make our marker type be
/// an empty struct rather than a caseless enum, and then it doesn't cost anything to instantiate
/// it.
///
/// ```swift
/// extension UnauthServiceSelector where Self == UnauthUsernamesServiceMarker {
///     static var usernames: Self { .init() }
/// }
/// ```
///
/// Finally, we observe that having a unique marker type is no longer needed if the shorthand names
/// are always used; we can make the marker generic over *any* type, and enforce that it's only used
/// with valid services by only defining static members for valid services. This is
/// ``UnauthServiceSelectorHelper``, though a client should never need to interact with it directly.
///
/// [SE-0299]: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0299-extend-generic-static-member-lookup.md
public protocol UnauthServiceSelector {
    associatedtype Api
}

/// A type used to declare new services for APIs taking ``UnauthServiceSelector``.
///
/// See ``UnauthServiceSelector/usernames`` for an example of how this is used.
public struct UnauthServiceSelectorHelper<Api>: UnauthServiceSelector {
    /// An escape hatch in case libsignal adds a new service protocol but forgets to add a selector
    /// for it.
    ///
    /// ## Usage
    ///
    /// ```swift
    /// extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any OopsNewService> {
    ///     static var oopsNewService: Self { .workaroundBecauseLibsignalForgotToExposeASelector() }
    /// }
    /// ```
    ///
    /// (We could just make `init` public as well, but this way it's more obvious that the
    /// workaround is meant to be temporary.)
    public static func workaroundBecauseLibsignalForgotToExposeASelector() -> Self { .init() }
}
