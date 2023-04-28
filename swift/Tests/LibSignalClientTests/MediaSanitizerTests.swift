//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#if SIGNAL_MEDIA_SUPPORTED

import XCTest
@testable import LibSignalClient

class Mp4SanitizerTests: TestCaseBase {
    func testEmptyMp4() {
        let input: [UInt8] = []
        XCTAssertThrowsError(try sanitizeMp4(input: SignalInputStreamAdapter(input), len: UInt64(input.count))) { error in
            if case SignalError.invalidMediaInput = error {} else { XCTFail("\(error)") }
        }
    }

    func testTruncatedMp4() {
        let input: [UInt8] = [0, 0, 0, 0]
        XCTAssertThrowsError(try sanitizeMp4(input: SignalInputStreamAdapter(input), len: UInt64(input.count))) { error in
            if case SignalError.invalidMediaInput = error {} else { XCTFail("\(error)") }
        }
    }

    func testNoopMinimalMp4() throws {
        let metadata = ftyp() + moov()
        let input = metadata + mdat()

        let sanitized = try sanitizeMp4(input: SignalInputStreamAdapter(input), len: UInt64(input.count))
        assertSanitizedMetadataEqual(sanitized, dataOffset: metadata.count, dataLen: input.count - metadata.count, metadata: nil)
    }

    func testMinimalMp4() throws {
        let metadata = ftyp() + moov()
        let input = ftyp() + mdat() + moov()

        let sanitized = try sanitizeMp4(input: SignalInputStreamAdapter(input), len: UInt64(input.count))
        assertSanitizedMetadataEqual(sanitized, dataOffset: ftyp().count, dataLen: input.count - metadata.count, metadata: metadata)
    }

    func testMp4IoError() throws {
        XCTAssertThrowsError(try sanitizeMp4(input: ErrorInputStream(), len: 1)) { error in
            if case SignalError.ioError = error {} else { XCTFail("\(error)") }
        }
    }
}

private struct TestIoError: Error {}

private class ErrorInputStream: SignalInputStream {
    func read(into buffer: UnsafeMutableRawBufferPointer) throws -> UInt {
        throw TestIoError()
    }

    func skip(by amount: UInt64) throws {
        throw TestIoError()
    }
}

private func ftyp() -> [UInt8] {
    var ftyp: [UInt8] = []
    ftyp.append(contentsOf: [0, 0, 0, 20]) // box size
    ftyp.append(contentsOf: "ftyp".utf8) // box type
    ftyp.append(contentsOf: "isom".utf8) // major_brand
    ftyp.append(contentsOf: [0, 0, 0, 0]) // minor_version
    ftyp.append(contentsOf: "isom".utf8) // compatible_brands
    return ftyp
}

private func moov() -> [UInt8] {
    var moov: [UInt8] = []
    // moov box header
    moov.append(contentsOf: [0, 0, 0, 56]) // box size
    moov.append(contentsOf: "moov".utf8) // box type

    // trak box (inside moov box)
    moov.append(contentsOf: [0, 0, 0, 48]) // box size
    moov.append(contentsOf: "trak".utf8) // box type

    // mdia box (inside trak box)
    moov.append(contentsOf: [0, 0, 0, 40]) // box size
    moov.append(contentsOf: "mdia".utf8) // box type

    // minf box (inside mdia box)
    moov.append(contentsOf: [0, 0, 0, 32]) // box size
    moov.append(contentsOf: "minf".utf8) // box type

    // stbl box (inside minf box)
    moov.append(contentsOf: [0, 0, 0, 24]) // box size
    moov.append(contentsOf: "stbl".utf8) // box type

    // stco box (inside stbl box)
    moov.append(contentsOf: [0, 0, 0, 16]) // box size
    moov.append(contentsOf: "stco".utf8) // box type
    moov.append(contentsOf: [0, 0, 0, 0]) // box version & flags
    moov.append(contentsOf: [0, 0, 0, 0]) // entry count

    return moov
}

private func mdat() -> [UInt8] {
    var mdat: [UInt8] = []
    mdat.append(contentsOf: [0, 0, 0, 8]) // box size
    mdat.append(contentsOf: "mdat".utf8) // box type
    return mdat
}

private func assertSanitizedMetadataEqual(_ sanitized: SanitizedMetadata, dataOffset: Int, dataLen: Int, metadata: (any Sequence<UInt8>)?) {
    if let metadata = metadata {
        XCTAssertNotNil(sanitized.metadata)
        XCTAssert(sanitized.metadata!.elementsEqual(metadata))
    } else {
        XCTAssertNil(sanitized.metadata)
    }
    XCTAssertEqual(sanitized.dataOffset, UInt64(dataOffset))
    XCTAssertEqual(sanitized.dataLen, UInt64(dataLen))
}

#endif
