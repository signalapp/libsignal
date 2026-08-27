//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthBackupsService: Sendable {
    /// Redeem a receipt to mark the account as eligible for the paid backup tier.
    ///
    /// After successful redemption, fetched BackupAuthCredentials will include the level on the
    /// provided receipt until the expiration time on the receipt.
    ///
    /// - Throws:
    ///   - ``SignalError/invalidReceipt(_:)`` if the receipt is invalid or expired
    ///   - ``SignalError/missingBackupId(_:)`` if there is no backup ID on the account
    ///   - the standard Signal network errors
    func redeemBackupReceipt(_ presentation: ReceiptCredentialPresentation) async throws
}

extension AuthenticatedChatConnection: AuthBackupsService {
    public func redeemBackupReceipt(_ presentation: ReceiptCredentialPresentation) async throws {
        try await NativeNice.AuthenticatedChatConnection_redeem_backup_receipt(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            presentation: presentation
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthBackupsService> {
    public static var backups: Self { .init() }
}
