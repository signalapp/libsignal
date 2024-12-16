//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Benchmark
import Foundation
import LibSignalClient

private let BENCHMARK_PLAINTEXT_SIZES = [100, 1000, 10000]

let privateKeyOperationsSuite = BenchmarkSuite(name: "PrivateKey") { suite in
    suite.benchmark("generate") {
        blackHole(PrivateKey.generate())
    }

    let privateKey = PrivateKey.generate()
    for plaintextSize in BENCHMARK_PLAINTEXT_SIZES {
        let bytes = Data((0..<plaintextSize).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
        suite.benchmark("generateSignature/\(plaintextSize)bytes") {
            blackHole(privateKey.generateSignature(message: bytes))
        }
    }

    let otherPublicKey = PrivateKey.generate().publicKey
    suite.benchmark("keyAgreement") {
        blackHole(privateKey.keyAgreement(with: otherPublicKey))
    }
}

let publicKeyOperationsSuite = BenchmarkSuite(name: "PublicKey") { suite in
    let privateKey = PrivateKey.generate()
    let publicKey = privateKey.publicKey
    let publicKeyBytes = publicKey.serialize()

    suite.benchmark("init") {
        blackHole(try! PublicKey(publicKeyBytes))
    }

    suite.benchmark("serialize") {
        blackHole(publicKey.serialize())
    }

    for plaintextSize in BENCHMARK_PLAINTEXT_SIZES {
        let bytes = Data((0..<plaintextSize).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
        let signature = privateKey.generateSignature(message: bytes)
        suite.benchmark("verifySignature/\(plaintextSize)bytes") {
            blackHole(try! publicKey.verifySignature(message: bytes, signature: signature))
        }
    }
}
