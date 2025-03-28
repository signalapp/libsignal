//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Benchmark
import LibSignalClient

func howTheIosAppOnceConvertedToHex(_ input: [UInt8]) -> String {
    var result = ""
    result.reserveCapacity(input.count * 2)
    for v in input {
        result += String(format: "%02x", v)
    }
    return result
}

let hexSuite = BenchmarkSuite(name: "Hex") { suite in
    let input = [UInt8](0..<64)

    suite.benchmark("libsignal") {
        blackHole(input.toHex())
    }

    suite.benchmark("oldImplementation") {
        blackHole(howTheIosAppOnceConvertedToHex(input))
    }
}
