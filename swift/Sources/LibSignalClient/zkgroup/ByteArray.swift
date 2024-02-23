//
// Copyright 2019-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class ByteArray {
    private let contents: [UInt8]

    init(_ newContents: [UInt8], checkValid: (SignalBorrowedBuffer) -> SignalFfiErrorRef?) throws {
        self.contents = newContents
        try self.withUnsafeBorrowedBuffer { buffer in
            try checkError(checkValid(buffer))
        }
    }

    init(newContents: [UInt8], expectedLength: Int, unrecoverable: Bool = false) throws {
        if newContents.count != expectedLength {
            throw SignalError.invalidType("\(type(of: self)) uses \(expectedLength) bytes, but tried to deserialize from an array of \(newContents.count) bytes")
        }
        self.contents = newContents
    }

    required init(contents: [UInt8]) throws {
        fatalError("must be overridden by subclasses to specify how to validate the contents")
    }

    public func serialize() -> [UInt8] {
        return self.contents
    }

    /// Passes a pointer to the serialized contents to `callback`.
    ///
    /// This pointer is only valid during the call to `callback` and should not be persisted.
    ///
    /// This method exists because Swift does not have a convenient, generic representation of C
    /// fixed-size arrays. Instead, it treats them as homogeneous tuples. (For example, `uint8_t[3]`
    /// is imported into Swift as `(UInt8, UInt8, UInt8)`. This method is intended to be called in a
    /// context where the argument type `Serialized` is inferred to be one of these homogeneous
    /// tuples representing a fixed-size array; using another type, or using the wrong size of
    /// array, is considered a programmer error and can result in arbitrary behavior (including
    /// violating type safety). So, uh, don't do that.
    func withUnsafePointerToSerialized<Serialized, Result>(_ callback: (UnsafePointer<Serialized>) throws -> Result) throws -> Result {
        precondition(MemoryLayout<Serialized>.alignment == 1, "not a fixed-sized array (tuple) of UInt8")

        return try self.contents.withUnsafeBytes { buffer in
            let expectedSize = MemoryLayout<Serialized>.size
            guard expectedSize == buffer.count else {
                throw SignalError.invalidType("\(type(of: self)) uses \(buffer.count) bytes, but was passed to a callback that uses \(expectedSize) bytes")
            }

            // Use assumingMemoryBound(to:) here rather than bindMemory(to:)
            // to avoid messing with Swift's notion of what the bytes are typed as
            // and therefore impeding or violating type-based transformations in the compiler.
            // This pointer should only be passed to C.
            let typedPointer = buffer.baseAddress!.assumingMemoryBound(to: Serialized.self)
            return try callback(typedPointer)
        }
    }

    /// Passes a pointer/length pair for the serialized contents to `callback`.
    ///
    /// Used for types that don't have a fixed-length representation.
    func withUnsafeBorrowedBuffer<Result>(_ callback: (SignalBorrowedBuffer) throws -> Result) throws -> Result {
        return try self.contents.withUnsafeBorrowedBuffer(callback)
    }
}
