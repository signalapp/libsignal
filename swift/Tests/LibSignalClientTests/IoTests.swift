//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

@testable import LibSignalClient
@testable import SignalFfi
import XCTest

class IoTests: TestCaseBase {
// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)
    func testReadIntoEmptyBuffer() throws {
        let input = [UInt8]("ABCDEFGHIJKLMNOPQRSTUVWXYZ".utf8)
        let inputStream = SignalInputStreamAdapter(input)
        let output = try withInputStream(inputStream) { input in
            try invokeFnReturningArray { output in
                SignalFfi.signal_testing_input_stream_read_into_zero_length_slice(output, input)
            }
        }
        XCTAssertEqual(input, output)
    }
#endif
}
