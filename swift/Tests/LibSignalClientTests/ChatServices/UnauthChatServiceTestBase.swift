//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthChatServiceTestBase<Service: Sendable>: TestCaseBase {
    typealias SelectorCheck = UnauthServiceSelectorHelper<Service>
    class var selector: SelectorCheck! { nil }

    override class func setUp() {
        super.setUp()
        precondition(self.selector != nil, "must override the selector property")
    }

    // XCTestCase does unusual things with its initializers for test case discovery,
    // so we can't override init(). Instead, we'll put our shared state in a helper type.
    // We specifically hide this to force tests to use the limited set of APIs in ``api``.
    private let state: UnauthChatServiceTestState = .init()

    internal var api: Service {
        // swiftlint:disable:next force_cast
        state.connection as! Service
    }
    internal var fakeRemote: FakeChatRemote {
        state.fakeRemote
    }
}

// Defined outside UnauthChatServiceTestBase because it's not generic.
private struct UnauthChatServiceTestState {
    let tokioAsyncContext = TokioAsyncContext()
    let connection: UnauthenticatedChatConnection
    let fakeRemote: FakeChatRemote

    init() {
        class NoOpListener: ConnectionEventsListener {
            func connectionWasInterrupted(_: UnauthenticatedChatConnection, error: Error?) {}
        }

        (connection, fakeRemote) = UnauthenticatedChatConnection.fakeConnect(
            tokioAsyncContext: tokioAsyncContext,
            listener: NoOpListener()
        )
    }
}

#endif
