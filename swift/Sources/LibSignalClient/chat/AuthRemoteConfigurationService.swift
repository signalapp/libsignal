//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public struct Badge: Equatable {
    public init(
        id: String,
        category: String,
        name: String,
        description: String,
        sprites6: [String],
        svg: String,
        svgs: [BadgeSvg]
    ) {
        self.id = id
        self.category = category
        self.name = name
        self.description = description
        self.sprites6 = sprites6
        self.svg = svg
        self.svgs = svgs
    }

    /// An ID that uniquely identifies the badge.
    public var id: String
    /// The category the badge falls in (such as "donor" or "other").
    public var category: String
    public var name: String
    public var description: String
    /// File names of raster image sprite sheets
    ///
    /// Sprite sheets live at https://updates2.signal.org/static/badges/
    ///
    /// The sprite sheets are (in order) scaled at: 0.75x, 1x, 1.5x, 2x, 3x, 4x
    public var sprites6: [String]
    /// File name of the scalable vector graphic representing this badge, for the "transparent" theme
    ///
    /// SVGs live at https://updates2.signal.org/static/badges/
    public var svg: String
    /// Pairs of light/dark SVG files designed for display at different sizes (in order: 16, 24, 36).
    ///
    /// SVGs live at https://updates2.signal.org/static/badges/
    public var svgs: [BadgeSvg]

}

public struct BadgeSvg: Equatable {
    public init(light: String, dark: String) {
        self.light = light
        self.dark = dark
    }

    /// File name of the scalable vector graphic for light mode.
    public var light: String
    /// File name of the scalable vector graphic for dark mode.
    public var dark: String
}

public struct TaggedBadges: Equatable {
    public init(badges: [String: Badge], etag: Data) {
        self.badges = badges
        self.etag = etag
    }

    /// A map of badge ID to the detailed information for that badge.
    public var badges: [String: Badge]
    /// An entity tag for `badges`. This may be supplied in a subsequent request
    /// to optimize bandwidth when the set of badges has not changed.
    public var etag: Data
}

public protocol AuthRemoteConfigurationService: Sendable {
    /// Returns detailed information for all configured badges, keyed by badge ID.
    ///
    /// Badge descriptions may contain localized strings. These are determined based on the Locale
    /// of the `AuthenticatedChatConnection`.
    ///
    /// Callers may cache a badges result for up to 1 day before checking (via
    /// etag) if there are any new updates.
    /// If the etag is up-to-date, this function will return `nil`.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func getBadges(
        etag: Data?,
    ) async throws -> TaggedBadges?
}

extension AuthenticatedChatConnection: AuthRemoteConfigurationService {

    public func getBadges(etag: Data?) async throws -> TaggedBadges? {
        return try await NativeNice.AuthenticatedChatConnection_get_badges(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            etag: etag,
        )
    }

}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthRemoteConfigurationService> {
    public static var remoteConfiguration: Self { .init() }
}
