//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import SignalFfi

#if canImport(SignalCoreKit)
import SignalCoreKit
#endif

class TestCaseBase: XCTestCase {
    // Use a static stored property for one-time initialization.
    static let loggingInitialized: Bool = {
#if canImport(SignalCoreKit)
        DDLog.add(DDOSLogger.sharedInstance)
#else
        signal_init_logger(SignalLogLevelTrace, .init(
            enabled: { _, _ in true },
            log: { _, level, file, line, message in
                let file = file.map { String(cString: $0) } ?? "<unknown>"
                file.withCString {
                    NSLog("(%u) [%s:%u] %s", level.rawValue, $0, line, message!)
                }
            },
            flush: {}
        ))
#endif
        return true
    }()

    override class func setUp() {
        precondition(loggingInitialized)
    }
}
