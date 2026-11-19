//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

#if !os(iOS) || targetEnvironment(simulator)

class BackupJsonExporterTests: TestCaseBase {
    /// Splits the canonical fixture into its unprefixed BackupInfo and length-prefixed frames.
    private func canonicalChunks() throws -> (backupInfo: Data, frames: [Data]) {
        let contents = readResource(forName: "canonical-backup.binproto")
        var bytes = contents
        var chunks: [Data] = []
        var backupInfo = Data()
        while !bytes.isEmpty {
            let start = bytes.startIndex
            var length = 0
            var shift = 0
            while true {
                let byte = try XCTUnwrap(bytes.first)
                bytes = bytes.dropFirst()
                length |= Int(byte & 0x7f) << shift
                if byte < 0x80 { break }
                shift += 7
                XCTAssertLessThan(shift, 32)
            }
            let frame = bytes.prefix(length)
            XCTAssertEqual(frame.count, length)
            if chunks.isEmpty {
                backupInfo = frame
            }
            chunks.append(contents[start..<frame.endIndex])
            bytes = bytes.dropFirst(length)
        }
        return (backupInfo, Array(chunks.dropFirst()))
    }

    private func delimited(_ frame: Data) -> Data {
        precondition(frame.count < 0x80, "test frame uses a single-byte length prefix")
        return Data([UInt8(frame.count)]) + frame
    }

    func testStreamsCanonicalBackup() throws {
        let (backupInfo, frames) = try canonicalChunks()
        let exporter = try BackupJsonExporter(backupInfo: backupInfo)
        var lines = [exporter.initialChunk]
        for batch in [frames.prefix(2), frames.dropFirst(2)] {
            let results = try exporter.exportFrames(batch.reduce(Data(), +))
            XCTAssertEqual(results.count, batch.count)
            for result in results {
                XCTAssertNil(result.errorMessage)
                lines.append(try XCTUnwrap(result.line))
            }
        }
        try exporter.finishExport()

        XCTAssertEqual(lines.count, frames.count + 1)
        for line in lines {
            XCTAssertFalse(line.contains("\n"))
            XCTAssertTrue(try JSONSerialization.jsonObject(with: Data(line.utf8)) is [String: Any])
        }
        XCTAssertTrue(lines[0].contains("\"version\""))
        XCTAssertTrue(lines[1].contains("\"account\""))
    }

    func testEmptyBatchWithoutValidation() throws {
        let (backupInfo, _) = try canonicalChunks()
        let exporter = try BackupJsonExporter(backupInfo: backupInfo, validate: false)
        XCTAssertTrue(try exporter.exportFrames(Data()).isEmpty)
        try exporter.finishExport()
    }

    func testFiltersDisappearingMessages() throws {
        let (backupInfo, _) = try canonicalChunks()
        // chatItem: { chatId: 1 authorId: 2 dateSent: 3 expiresInMs: 1 }
        let frame = Data(base64Encoded: "IggIARACGAMoAQ==")!
        for validate in [true, false] {
            let exporter = try BackupJsonExporter(backupInfo: backupInfo, validate: validate)
            let results = try exporter.exportFrames(delimited(frame))
            XCTAssertEqual(results.count, 1)
            let result = try XCTUnwrap(results.first)
            XCTAssertNil(result.line)
            if validate {
                XCTAssertFalse(try XCTUnwrap(result.errorMessage).isEmpty)
                // No AccountData frame was provided.
                XCTAssertThrowsError(try exporter.finishExport()) { error in
                    XCTAssertTrue(error is MessageBackupValidationError)
                }
            } else {
                XCTAssertNil(result.errorMessage)
                try exporter.finishExport()
            }
        }
    }

    func testStripsViewOnceAttachmentsAndRevisions() throws {
        let (backupInfo, _) = try canonicalChunks()
        let exporter = try BackupJsonExporter(backupInfo: backupInfo, validate: false)
        // A view-once chat item and revision, both with a downloaded attachment.
        // Same protobuf fixture as the Kotlin exporter test.
        let frame = Data(base64Encoded: "IhwIChALGAwyDQgKEAsYCZIBBAoCGAGSAQQKAhgB")!
        let results = try exporter.exportFrames(delimited(frame))
        XCTAssertEqual(results.count, 1)
        let result = try XCTUnwrap(results.first)
        XCTAssertNil(result.errorMessage)
        let line = try XCTUnwrap(result.line)
        let actual = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? NSDictionary
        let expected = """
            {"chatItem":{"chatId":"10","authorId":"11","dateSent":"12","viewOnceMessage":{},
            "revisions":[{"chatId":"10","authorId":"11","dateSent":"9","viewOnceMessage":{}}]}}
            """
        XCTAssertEqual(actual, try JSONSerialization.jsonObject(with: Data(expected.utf8)) as? NSDictionary)
        try exporter.finishExport()
    }

    func testReportsFrameErrorsWithoutAbortingBatch() throws {
        let (backupInfo, frames) = try canonicalChunks()
        let exporter = try BackupJsonExporter(backupInfo: backupInfo)
        // An empty protobuf Frame is parseable and renderable, but semantically invalid.
        let results = try exporter.exportFrames(Data([0]) + frames.reduce(Data(), +))
        XCTAssertEqual(results.count, frames.count + 1)
        let invalid = try XCTUnwrap(results.first)
        XCTAssertNil(invalid.line)
        XCTAssertFalse(try XCTUnwrap(invalid.errorMessage).isEmpty)
        for result in results.dropFirst() {
            XCTAssertNotNil(result.line)
            XCTAssertNil(result.errorMessage)
        }
        try exporter.finishExport()
    }

    func testFinishValidationCanBeDisabled() throws {
        let (backupInfo, frames) = try canonicalChunks()
        for validate in [true, false] {
            let exporter = try BackupJsonExporter(backupInfo: backupInfo, validate: validate)
            // Skip AccountData to trigger a whole-backup validation error.
            let results = try exporter.exportFrames(frames.dropFirst().reduce(Data(), +))
            if validate {
                XCTAssertThrowsError(try exporter.finishExport()) { error in
                    let validationError = error as? MessageBackupValidationError
                    XCTAssertNotNil(validationError)
                    XCTAssertFalse(validationError?.errorMessage.isEmpty ?? true)
                }
            } else {
                XCTAssertTrue(results.allSatisfy { $0.errorMessage == nil })
                try exporter.finishExport()
            }
        }
    }

    func testRejectsMalformedBackupInfo() {
        for validate in [true, false] {
            XCTAssertThrowsError(try BackupJsonExporter(backupInfo: Data([0xff]), validate: validate)) { error in
                XCTAssertTrue(error is MessageBackupValidationError)
            }
        }
    }

    func testRejectsMalformedFramesEvenWithoutValidation() throws {
        let (backupInfo, _) = try canonicalChunks()
        for validate in [true, false] {
            for frame in [Data([0x02, 0x01]), Data([0x01, 0xff])] {
                let exporter = try BackupJsonExporter(backupInfo: backupInfo, validate: validate)
                XCTAssertThrowsError(try exporter.exportFrames(frame)) { error in
                    XCTAssertTrue(error is MessageBackupValidationError)
                }
            }
        }
    }
}

#endif
