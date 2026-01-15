//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

internal func withInputStream<Result>(
    _ stream: SignalInputStream,
    _ body: (SignalConstPointerFfiInputStreamStruct) throws -> Result
) throws -> Result {
    func ffiShimRead(
        stream_ctx: UnsafeMutableRawPointer?,
        pAmountRead: UnsafeMutablePointer<Int>?,
        buf: SignalBorrowedMutableBuffer,
    ) -> Int32 {
        let streamContext = stream_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SignalInputStream>.self)
        return streamContext.pointee.catchCallbackErrors { stream in
            let buf = UnsafeMutableRawBufferPointer(start: buf.base, count: buf.length)
            let amountRead = try stream.read(into: buf)
            pAmountRead!.pointee = amountRead
        }
    }

    func ffiShimSkip(stream_ctx: UnsafeMutableRawPointer?, amount: UInt64) -> Int32 {
        let streamContext = stream_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SignalInputStream>.self)
        return streamContext.pointee.catchCallbackErrors { stream in
            try stream.skip(by: amount)
        }
    }

    return try rethrowCallbackErrors(stream) {
        var ffiStream = SignalFfi.SignalInputStream(
            ctx: $0,
            read: ffiShimRead as SignalFfiBridgeInputStreamRead,
            skip: ffiShimSkip as SignalFfiBridgeInputStreamSkip,
            destroy: { _ in }
        )
        return try withUnsafePointer(to: &ffiStream) {
            try body(SignalConstPointerFfiInputStreamStruct(raw: $0))
        }
    }
}
