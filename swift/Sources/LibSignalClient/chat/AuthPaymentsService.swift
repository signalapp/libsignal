//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public struct CurrencyConversions: Equatable {
    public init(timestamp: Date, currencies: [Currency]) {
        self.timestamp = timestamp
        self.currencies = currencies
    }
    internal init(fromInternal cci: CurrencyConversionsInternal) {
        self.timestamp = cci.timestampMs
        self.currencies = cci.currencies.map { c in
            Currency(base: c.base, conversions: Dictionary(uniqueKeysWithValues: c.conversions))
        }
    }

    public let timestamp: Date
    public let currencies: [Currency]
}
public struct Currency: Equatable {
    public init(base: String, conversions: [String: String]) {
        self.base = base
        self.conversions = conversions
    }

    public let base: String
    /// The values of this map are decimal conversion rates.
    public let conversions: [String: String]
}

public protocol AuthPaymentsService: Sendable {
    /// Return the current currency conversion rates.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func getCurrencyConversions() async throws -> CurrencyConversions
}

extension AuthenticatedChatConnection: AuthPaymentsService {

    public func getCurrencyConversions() async throws -> CurrencyConversions {
        return CurrencyConversions(
            fromInternal: try await NativeNice.AuthenticatedChatConnection_get_currency_conversions(
                asyncContext: self.tokioAsyncContext,
                chat: self,
            )
        )
    }

}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthPaymentsService> {
    public static var payments: Self { .init() }
}
