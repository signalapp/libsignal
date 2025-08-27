//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

/// Represents a type that can be "borrowed" into an FFI-compatible form using a scope-based callback.
internal protocol BorrowForFfi {
    associatedtype Borrowed
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) throws -> Result
}

/// Invokes `callback` with the borrowed form of each `input`
internal func withAllBorrowed<Result, each Input: BorrowForFfi>(
    _ input: repeat each Input,
    in callback: (repeat (each Input).Borrowed) throws -> Result
) throws -> Result {
    return try withoutActuallyEscaping(callback) { callback in
        // Optimization: allocate the correct-sized array up front.
        var count = 0
        for _ in repeat (each Input).self {
            count += 1
        }

        // Make space for each of the "borrowed" values.
        // If we had first-class references like Rust we could do:
        //   var borrows: (repeat (each Input)?) = (repeat nil)
        //   var places = (repeat &mut (each borrows))
        // and then iterate over `inputs` and `places` together.
        // But we don't, so we instead build up an array of pointers
        // to stack locations and read them all out at the end.
        // And we use a stack array instead of a full Array as a microoptimization.
        // (We could put the values directly in the array instead using Any,
        // but then we have to downcast them to get them out.)
        return try withUnsafeTemporaryAllocation(of: UnsafeRawPointer.self, capacity: count) { borrows in
            var nextIndex = count - 1

            // Because the "borrow" operations have to be nested to work correctly,
            // we build up a compound operation whose final (innermost) step is
            // "actually invoke the callback". The wrapping layers are described in the loop below.
            var operation = {
                // The "innermost" operation reads out all the values from the pointers in `borrows`
                // and invokes the user's callback.
                var pointerIter = borrows.makeIterator()
                let borrows = (repeat pointerIter.next()!.load(as: (each Input).Borrowed.self))
                return try callback(repeat each borrows)
            }

            for next in repeat each input {
                // For each input, we wrap `operation` ("the rest of the work") in "borrow this input,
                // store it for later, and invoke the rest of the work".
                // Note that this only works because we're promising not to use the array after the
                // operation is complete.
                operation = { [operation] in
                    return try next.withBorrowed { borrowed in
                        try withUnsafePointer(to: borrowed) { pointer in
                            borrows[nextIndex] = UnsafeRawPointer(pointer)
                            nextIndex -= 1
                            return try operation()
                        }
                    }
                }
            }

            // Finally, we can invoke our stacked operation, which looks something like this:
            // - Borrow input3, then...
            // - Borrow input2, then...
            // - Borrow input1, then...
            // - Read out (input1, input2, input3) and invoke the original callback.
            return try operation()
        }
    }
}

// Overloads for the short cases, to help with optimization.

internal func withAllBorrowed<Result, Input1: BorrowForFfi>(
    _ input1: Input1,
    in callback: (Input1.Borrowed) throws -> Result
) throws -> Result {
    return try input1.withBorrowed(callback)
}

internal func withAllBorrowed<Result, Input1: BorrowForFfi, Input2: BorrowForFfi>(
    _ input1: Input1,
    _ input2: Input2,
    in callback: (Input1.Borrowed, Input2.Borrowed) throws -> Result
) throws -> Result {
    // Borrow in reverse order, like the variadic one does.
    return try input2.withBorrowed { input2 in
        try input1.withBorrowed { input1 in
            try callback(input1, input2)
        }
    }
}

internal func withAllBorrowed<Result, Input1: BorrowForFfi, Input2: BorrowForFfi, Input3: BorrowForFfi>(
    _ input1: Input1,
    _ input2: Input2,
    _ input3: Input3,
    in callback: (Input1.Borrowed, Input2.Borrowed, Input3.Borrowed) throws -> Result
) throws -> Result {
    // Borrow in reverse order, like the variadic one does.
    return try input3.withBorrowed { input3 in
        try input2.withBorrowed { input2 in
            try input1.withBorrowed { input1 in
                try callback(input1, input2, input3)
            }
        }
    }
}

extension NativeHandleOwner: BorrowForFfi {
    typealias Borrowed = PointerType
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) rethrows -> Result {
        return try self.withNativeHandle(callback)
    }
}

extension ByteArray: BorrowForFfi {
    typealias Borrowed = SignalBorrowedBuffer
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) rethrows -> Result {
        return try self.withUnsafeBorrowedBuffer(callback)
    }
}

extension ServiceId: BorrowForFfi {
    typealias Borrowed = UnsafePointer<ServiceIdStorage>
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) rethrows -> Result {
        return try self.withPointerToFixedWidthBinary(callback)
    }
}

extension Randomness: BorrowForFfi {
    typealias Borrowed = UnsafePointer<SignalRandomnessBytes>
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) rethrows -> Result {
        return try self.withUnsafePointerToBytes(callback)
    }
}

extension Data: BorrowForFfi {
    typealias Borrowed = SignalBorrowedBuffer
    func withBorrowed<Result>(_ callback: (SignalBorrowedBuffer) throws -> Result) rethrows -> Result {
        return try self.withUnsafeBorrowedBuffer(callback)
    }
}

extension Optional: BorrowForFfi where Wrapped: BorrowForFfi, Wrapped.Borrowed == SignalBorrowedBuffer {
    typealias Borrowed = SignalOptionalBorrowedSliceOfc_uchar
    func withBorrowed<Result>(_ callback: (SignalOptionalBorrowedSliceOfc_uchar) throws -> Result) throws -> Result {
        guard let self else {
            return try callback(.init())
        }
        return try self.withBorrowed { buffer in
            try callback(.init(present: true, value: buffer))
        }
    }
}

internal struct ContiguousBytesWrapper<Inner: ContiguousBytes>: BorrowForFfi {
    var inner: Inner

    typealias Borrowed = SignalBorrowedBuffer
    func withBorrowed<Result>(_ callback: (SignalBorrowedBuffer) throws -> Result) rethrows -> Result {
        return try self.inner.withUnsafeBorrowedBuffer(callback)
    }
}

extension BorrowForFfi {
    // A trick to expose a contextual shortcut where a BorrowForFfi instance is expected.
    // See <https://github.com/swiftlang/swift-evolution/blob/main/proposals/0299-extend-generic-static-member-lookup.md>.
    static func bytes<Bytes: ContiguousBytes>(_ bytes: Bytes) -> Self where Self == ContiguousBytesWrapper<Bytes> {
        .init(inner: bytes)
    }
}

extension UUID: BorrowForFfi {
    typealias Borrowed = UnsafePointer<uuid_t>
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) rethrows -> Result {
        return try withUnsafePointer(to: self.uuid, callback)
    }
}

internal struct FixedLengthWrapper<FixedLengthRepr>: BorrowForFfi {
    var inner: ByteArray

    typealias Borrowed = UnsafePointer<FixedLengthRepr>
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) throws -> Result {
        return try self.inner.withUnsafePointerToSerialized(callback)
    }
}

internal struct OptionalFixedLengthWrapper<FixedLengthRepr>: BorrowForFfi {
    var inner: ByteArray?

    typealias Borrowed = UnsafePointer<FixedLengthRepr>?
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) throws -> Result {
        if let inner {
            try inner.withUnsafePointerToSerialized(callback)
        } else {
            try callback(nil)
        }
    }
}

extension BorrowForFfi {
    static func fixed<FixedLengthRepr>(_ serialized: ByteArray) -> Self
    where Self == FixedLengthWrapper<FixedLengthRepr> {
        .init(inner: serialized)
    }

    static func fixed<FixedLengthRepr>(_ serialized: ByteArray?) -> Self
    where Self == OptionalFixedLengthWrapper<FixedLengthRepr> {
        .init(inner: serialized)
    }
}

protocol FfiBorrowedSlice {
    associatedtype Element
    // We ought to be able to make the requirement init(base:length:), like the one that gets synthesized,
    // but that doesn't seem to work.
    init(_ buffer: UnsafeBufferPointer<Element>)
}

extension SignalBorrowedSliceOfConstPointerSessionRecord: FfiBorrowedSlice {
    init(_ buffer: UnsafeBufferPointer<SignalConstPointerSessionRecord>) {
        self.init(base: buffer.baseAddress, length: buffer.count)
    }
}

extension SignalBorrowedSliceOfConstPointerProtocolAddress: FfiBorrowedSlice {
    init(_ buffer: UnsafeBufferPointer<SignalConstPointerProtocolAddress>) {
        self.init(base: buffer.baseAddress, length: buffer.count)
    }
}

extension SignalBorrowedSliceOfConstPointerPublicKey: FfiBorrowedSlice {
    init(_ buffer: UnsafeBufferPointer<SignalConstPointerPublicKey>) {
        self.init(base: buffer.baseAddress, length: buffer.count)
    }
}

internal struct ElementsWrapper<FfiType: FfiBorrowedSlice>: BorrowForFfi {
    var inner: [FfiType.Element]

    typealias Borrowed = FfiType
    func withBorrowed<Result>(_ callback: (Borrowed) throws -> Result) throws -> Result {
        return try self.inner.withUnsafeBufferPointer {
            try callback(.init($0))
        }
    }
}

extension BorrowForFfi {
    static func slice<FfiType: FfiBorrowedSlice>(_ input: [FfiType.Element]) -> Self
    where Self == ElementsWrapper<FfiType> {
        .init(inner: input)
    }
}
