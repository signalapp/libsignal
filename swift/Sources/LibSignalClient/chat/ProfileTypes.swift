//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// A URL that points to a Signal CDN
public struct CdnUrl: Sendable, Equatable {
    public let url: String

    internal init(withPreValidatedUrl url: String) {
        self.url = url
    }

    /// - Returns:
    ///   - `nil` if the given URL isn't valid
    public init?(_ url: String) {
        let isValid = try! NativeNice.CdnUrl_validate(url: url)
        if !isValid {
            return nil
        }
        self.url = url
    }
}
