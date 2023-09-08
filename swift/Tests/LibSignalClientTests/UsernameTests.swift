//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import LibSignalClient

class UsernameTests: TestCaseBase {

    func testTheBasicFlow() throws {
        let candidates = try Username.candidates(from: "hel10")
        let username = candidates[0]
        XCTAssertEqual(32, username.hash.count)
        let proof = username.generateProof()
        XCTAssertGreaterThan(proof.count, 0)

        try Username.verify(proof: proof, forHash: username.hash)
        var hash = username.hash
        hash.shuffle()
        XCTAssertThrowsError(
            try Username.verify(proof: proof, forHash: hash)
        )
    }

    func testCandidatesGeneration() throws {
        XCTAssertThrowsError(
            try Username.candidates(from: "hi", withValidLengthWithin: 3...10)
        )
        XCTAssertThrowsError(
            try Username.candidates(from: "a_very_long_nickname", withValidLengthWithin: 3...10)
        )
        let nickname = "SiGNAl"
        let candidates = try Username.candidates(from: nickname)
        XCTAssertEqual(20, candidates.count)
        for candidate in candidates {
            XCTAssert(String(describing: candidate).starts(with: nickname))
        }
    }

    func testInvalidNicknames() throws {
        for nickname in ["hi", "way_too_long_to_be_a_reasonable_nickname", "I⍰Unicode", "s p a c e s", "0zerostart"] {
            XCTAssertThrowsError(try Username.candidates(from: nickname))
        }
    }

    func testValidUsernameHashing() throws {
        let username = try Username("he110.42")
        XCTAssertEqual(32, username.hash.count)
        XCTAssertEqual([
            0xf6, 0x3f, 0x05, 0x21, 0xeb, 0x3a, 0xdf, 0xe1,
            0xd9, 0x36, 0xf4, 0xb6, 0x26, 0xb8, 0x95, 0x58,
            0x48, 0x35, 0x07, 0xfb, 0xdb, 0x83, 0x8f, 0xc5,
            0x54, 0xaf, 0x05, 0x91, 0x11, 0xcf, 0x32, 0x2e], username.hash)
    }

    func testInvalidHash() throws {
        let username = try Username("hello_signal.42")
        var hash = username.hash
        let proof = username.generateProof()

        hash.shuffle()
        XCTAssertThrowsError(try Username.verify(proof: proof, forHash: hash))
    }

    func testInvalidUsernames() throws {
        for rawName in ["0zerostart.01", "zero.00", "short_zero.0", "short_one.1"] {
            XCTAssertThrowsError(try Username(rawName))
        }
    }

    func testSpecificErrorType() throws {
        do {
            _ = try Username("I⍰Unicode.42")
            XCTFail("Should have failed")
        } catch SignalError.badNicknameCharacter {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }

    func testUsernameLinkWorksEndToEnd() throws {
        let original = try Username("SiGNAl.42")
        let (randomness, linkBytes) = try original.createLink()
        let recreated = try Username(fromLink: linkBytes, withRandomness: randomness)
        XCTAssertEqual(original, recreated)
    }

    func testUsernameLinkInvalidEntropySize() throws {
        do {
            let randomness = [UInt8](repeating: 0, count: 16)
            let linkBytes = [UInt8](repeating: 0, count: 32)
            _ = try Username(fromLink: linkBytes, withRandomness: randomness)
            XCTFail("Should have failed")
        } catch SignalError.usernameLinkInvalidEntropyDataLength {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }

    func testUsernameLinkInvalidLinkBytes() throws {
        do {
            let randomness = [UInt8](repeating: 0, count: 32)
            let linkBytes = [UInt8](repeating: 0, count: 32)
            _ = try Username(fromLink: linkBytes, withRandomness: randomness)
            XCTFail("Should have failed")
        } catch SignalError.usernameLinkInvalid {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }
}
