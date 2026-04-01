//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol AuthMessagesService: Sendable {
    /// Get an attachment upload form
    ///
    /// - Throws:
    ///   - ``SignalError/uploadTooLarge(_:)`` if ``uploadSize`` is too large
    ///   - the standard Signal network errors
    func getUploadForm(uploadSize: UInt64) async throws -> UploadForm
}

extension AuthenticatedChatConnection: AuthMessagesService {
    public func getUploadForm(uploadSize: UInt64) async throws -> UploadForm {
        return try UploadForm(
            consuming: try await self.tokioAsyncContext
                .invokeAsyncFunction { promise, tokioAsyncContext in
                    withNativeHandle { chatService in
                        signal_authenticated_chat_connection_get_upload_form(
                            promise,
                            tokioAsyncContext.const(),
                            chatService.const(),
                            uploadSize,
                        )
                    }
                }
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthMessagesService> {
    public static var attachments: Self { .init() }
}
