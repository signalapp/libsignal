//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol AuthMessagesService: Sendable {
    /// Get an attachment upload form
    ///
    /// Throws only if the request cannot be completed.
    func getUploadForm() async throws -> UploadForm
}

extension AuthenticatedChatConnection: AuthMessagesService {
    public func getUploadForm() async throws -> UploadForm {
        return try UploadForm(
            consuming: try await self.tokioAsyncContext
                .invokeAsyncFunction { promise, tokioAsyncContext in
                    withNativeHandle { chatService in
                        signal_authenticated_chat_connection_get_upload_form(
                            promise,
                            tokioAsyncContext.const(),
                            chatService.const(),
                        )
                    }
                }
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthMessagesService> {
    public static var attachments: Self { .init() }
}
