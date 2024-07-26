//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

internal func withInputStream<Result>(_ stream: SignalInputStream, _ body: (UnsafePointer<SignalFfi.SignalInputStream>) throws -> Result) throws -> Result {
    func ffiShimRead(
        stream_ctx: UnsafeMutableRawPointer?,
        pBuf: UnsafeMutablePointer<UInt8>?,
        bufLen: Int,
        pAmountRead: UnsafeMutablePointer<Int>?
    ) -> Int32 {
        let streamContext = stream_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SignalInputStream>.self)
        return streamContext.pointee.catchCallbackErrors { stream in
            let buf = UnsafeMutableRawBufferPointer(start: pBuf, count: bufLen)
            let amountRead = try stream.read(into: buf)
            pAmountRead!.pointee = amountRead
            return 0
        }
    }

    func ffiShimSkip(stream_ctx: UnsafeMutableRawPointer?, amount: UInt64) -> Int32 {
        let streamContext = stream_ctx!.assumingMemoryBound(to: ErrorHandlingContext<SignalInputStream>.self)
        return streamContext.pointee.catchCallbackErrors { stream in
            try stream.skip(by: amount)
            return 0
        }
    }

    return try rethrowCallbackErrors(stream) {
        var ffiStream = SignalFfi.SignalInputStream(
            ctx: $0,
            read: ffiShimRead as SignalRead,
            skip: ffiShimSkip as SignalSkip
        )
        return try body(&ffiStream)
    }
}
