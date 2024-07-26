//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

class TestCaseBase: XCTestCase {
    // Use a static stored property for one-time initialization.
    static let loggingInitialized: Bool = {
        struct LogToNSLog: LibsignalLogger {
            func log(level: LibsignalLogLevel, file: UnsafePointer<CChar>?, line: UInt32, message: UnsafePointer<CChar>) {
                let abbreviation: String
                switch level {
                case .error: abbreviation = "E"
                case .warn: abbreviation = "W"
                case .info: abbreviation = "I"
                case .debug: abbreviation = "D"
                case .trace: abbreviation = "T"
                }
                let file = file.map { String(cString: $0) } ?? "<unknown>"
                NSLog("%@ [%@:%u] %s", abbreviation, file, line, message)
            }

            func flush() {}
        }
        LogToNSLog().setUpLibsignalLogging(level: .trace)
        return true
    }()

    override class func setUp() {
        precondition(self.loggingInitialized)
    }
}
