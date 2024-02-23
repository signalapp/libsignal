//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

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
            0xF6, 0x3F, 0x05, 0x21, 0xEB, 0x3A, 0xDF, 0xE1,
            0xD9, 0x36, 0xF4, 0xB6, 0x26, 0xB8, 0x95, 0x58,
            0x48, 0x35, 0x07, 0xFB, 0xDB, 0x83, 0x8F, 0xC5,
            0x54, 0xAF, 0x05, 0x91, 0x11, 0xCF, 0x32, 0x2E,
        ], username.hash)
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

    func testValidUsernamesFromParts() throws {
        let jimio01 = try Username(nickname: "jimio", discriminator: "01", withValidLengthWithin: 3...32)
        XCTAssertEqual("jimio.01", jimio01.value)
        try Username.verify(proof: jimio01.generateProof(), forHash: jimio01.hash)

        XCTAssertEqual(
            "jimio.\(UInt64.max)",
            try Username(
                nickname: "jimio",
                discriminator: "\(UInt64.max)",
                withValidLengthWithin: 3...32
            ).value
        )
    }

    func testCorrectErrorsForInvalidUsernamesFromParts() throws {
        do {
            _ = try Username(nickname: "", discriminator: "01", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.nicknameCannotBeEmpty {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "1digit", discriminator: "01", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.nicknameCannotStartWithDigit {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "s p a c e s", discriminator: "01", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.badNicknameCharacter {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "abcde", discriminator: "01", withValidLengthWithin: 10...32)
            XCTFail("should have failed")
        } catch SignalError.nicknameTooShort {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "abcde", discriminator: "01", withValidLengthWithin: 3...4)
            XCTFail("should have failed")
        } catch SignalError.nicknameTooLong {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "jimio", discriminator: "", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.usernameDiscriminatorCannotBeEmpty {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "jimio", discriminator: "00", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.usernameDiscriminatorCannotBeZero {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "jimio", discriminator: "012", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.usernameDiscriminatorCannotHaveLeadingZeros {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "jimio", discriminator: "+12", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.badDiscriminatorCharacter {
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        do {
            _ = try Username(nickname: "jimio", discriminator: "18446744073709551616", withValidLengthWithin: 3...32)
            XCTFail("should have failed")
        } catch SignalError.usernameDiscriminatorTooLarge {
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testUsernameLinkWorksEndToEnd() throws {
        let original = try Username("SiGNAl.42")
        let (randomness, linkBytes) = try original.createLink()
        let recreated = try Username(fromLink: linkBytes, withRandomness: randomness)
        XCTAssertEqual(original, recreated)
    }

    func testUsernameLinkWithReusedEntropy() throws {
        let original = try Username("SiGNAl.42")
        let (randomness, linkBytes) = try original.createLink()
        let recreated = try Username(fromLink: linkBytes, withRandomness: randomness)
        XCTAssertEqual(original, recreated)

        let (newRandomness, newLinkBytes) = try original.createLink(previousEntropy: randomness)
        XCTAssertEqual(randomness, newRandomness)
        XCTAssertNotEqual(linkBytes, newLinkBytes)
        let newRecreated = try Username(fromLink: newLinkBytes, withRandomness: randomness)
        XCTAssertEqual(original, newRecreated)
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
