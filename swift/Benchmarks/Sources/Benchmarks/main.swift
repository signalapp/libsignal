//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Benchmark
import LibSignalClient

Benchmark.main([
    groupSendEndorsementsSuite,
    privateKeyOperationsSuite,
    publicKeyOperationsSuite,
])

/// Attempts to prevent the value of `x` from being discarded by the optimizer.
///
/// See https://github.com/google/swift-benchmark/issues/69
@inline(__always)
internal func blackHole<T>(_ x: T) {
    @_optimize(none)
    func assumePointeeIsRead(_: UnsafeRawPointer) {}

    withUnsafePointer(to: x) { assumePointeeIsRead($0) }
}
