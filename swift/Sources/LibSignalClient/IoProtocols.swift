//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// An input stream of bytes.
///
/// This protocol is implemented for `FileHandle`.
public protocol SignalInputStream: AnyObject {
    /// Read an amount of bytes from the input stream.
    ///
    /// The actual amount of bytes returned may be smaller than the buffer provided by the caller, for any reason;
    /// however, reading zero bytes always indicates that the end of the stream has been reached.
    ///
    /// - Parameter buffer: The buffer to read the bytes into.
    /// - Returns: The actual number of bytes read.
    /// - Throws: If an I/O error occurred while reading from the input.
    func read(into buffer: UnsafeMutableRawBufferPointer) throws -> UInt

    /// Skip an amount of bytes in the input stream.
    ///
    /// If the requested number of bytes could not be skipped for any reason, including if the end of stream was
    /// reached, an error must be raised.
    ///
    /// - Parameter amount: The amount of bytes to skip.
    /// - Throws:If an I/O error occurred while skipping the bytes in the input.
    func skip(by amount: UInt64) throws
}

/// An error thrown by `SignalInputStreamAdapter`.
public enum SignalInputStreamError: Error {
    /// The end of the input stream was reached while attempting to `skip()`.
    case unexpectedEof
}

extension FileHandle: SignalInputStream {
    public func read(into buffer: UnsafeMutableRawBufferPointer) throws -> UInt {
        let data = self.readData(ofLength: buffer.count)
        return UInt(data.copyBytes(to: buffer))
    }

    public func skip(by amount: UInt64) throws {
        self.seek(toFileOffset: self.offsetInFile + amount)
    }
}

/// An adapter implementing `SignalInputStream` for any `Collection<UInt8>`.
public class SignalInputStreamAdapter<Inner>: SignalInputStream where Inner: Collection<UInt8> {
    var inner: Inner.SubSequence

    public init(_ inner: Inner) {
        self.inner = inner[...]
    }

    public func read(into buffer: UnsafeMutableRawBufferPointer) throws -> UInt {
        let amount = min(buffer.count, inner.count)
        buffer.copyBytes(from: inner.prefix(amount))
        inner = inner.dropFirst(amount)
        return UInt(amount)
    }

    public func skip(by amount: UInt64) throws {
        if amount > UInt64(inner.count) {
            throw SignalInputStreamError.unexpectedEof
        }
        inner = inner.dropFirst(Int(amount))
    }
}
