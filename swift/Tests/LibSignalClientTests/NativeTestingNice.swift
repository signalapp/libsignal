//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

// swiftlint:disable superfluous_disable_command
// swiftlint and swift-format disagree on some comma formatting
// swiftlint:disable comma
// swiftlint:disable large_tuple
// Some of our type names grow long
// swiftlint:disable type_name

// swiftlint:disable explicit_init_for_public_struct

#if !os(iOS) || targetEnvironment(simulator)

import Foundation
import SignalFfi
@testable import LibSignalClient

enum FfiBorrowedSliceConstructor_SignalBorrowedSliceOfCStringPtr_StringConverter: FfiBorrowedSliceConstructor {
    public typealias BorrowedSlice = SignalFfi.SignalBorrowedSliceOfCStringPtr
    public typealias Element = StringConverter.FfiArg
    public static func construct(
        _ buffer: UnsafeBufferPointer<Element>,
    ) -> BorrowedSlice {
        BorrowedSlice(base: buffer.baseAddress, length: buffer.count)
    }
}

enum FfiBorrowedSliceConstructor_SignalBorrowedSliceOfMySimpleTestEnumFfiArg_DerivedArgConverterMySimpleTestEnum:
    FfiBorrowedSliceConstructor
{
    public typealias BorrowedSlice = SignalFfi.SignalBorrowedSliceOfMySimpleTestEnumFfiArg
    public typealias Element = DerivedArgConverterMySimpleTestEnum.FfiArg
    public static func construct(
        _ buffer: UnsafeBufferPointer<Element>,
    ) -> BorrowedSlice {
        BorrowedSlice(base: buffer.baseAddress, length: buffer.count)
    }
}

enum FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCStringPtr_StringConverter:
    FfiOwnedBufferOfMaxAlignedProject
{
    public typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedCStringPtr
    public typealias Element = StringConverter.FfiReturn
    public static func empty() -> Buffer {
        Buffer()
    }
    public static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    public static func typeErased(
        _ buffer: Buffer
    ) -> SignalOwnedBufferOfMaxAlignedc_void {
        SignalOwnedBufferOfMaxAlignedc_void(
            base: UnsafeMutableRawPointer(buffer.base),
            length: buffer.length,
            size_bytes: buffer.size_bytes,
        )
    }
}

enum
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCopyBackupMediaOutFfiResult_DerivedReturnConverterCopyBackupMediaOut:
        FfiOwnedBufferOfMaxAlignedProject
{
    public typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedCopyBackupMediaOutFfiResult
    public typealias Element = DerivedReturnConverterCopyBackupMediaOut.FfiReturn
    public static func empty() -> Buffer {
        Buffer()
    }
    public static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    public static func typeErased(
        _ buffer: Buffer
    ) -> SignalOwnedBufferOfMaxAlignedc_void {
        SignalOwnedBufferOfMaxAlignedc_void(
            base: UnsafeMutableRawPointer(buffer.base),
            length: buffer.length,
            size_bytes: buffer.size_bytes,
        )
    }
}

enum
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedMySimpleTestEnumFfiResult_DerivedReturnConverterMySimpleTestEnum:
        FfiOwnedBufferOfMaxAlignedProject
{
    public typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedMySimpleTestEnumFfiResult
    public typealias Element = DerivedReturnConverterMySimpleTestEnum.FfiReturn
    public static func empty() -> Buffer {
        Buffer()
    }
    public static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    public static func typeErased(
        _ buffer: Buffer
    ) -> SignalOwnedBufferOfMaxAlignedc_void {
        SignalOwnedBufferOfMaxAlignedc_void(
            base: UnsafeMutableRawPointer(buffer.base),
            length: buffer.length,
            size_bytes: buffer.size_bytes,
        )
    }
}

enum
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32:
        FfiOwnedBufferOfMaxAlignedProject
{
    public typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedc_uchar32
    public typealias Element = FixedByteArrayConverter<FixedByteArrayHelper32>.FfiReturn
    public static func empty() -> Buffer {
        Buffer()
    }
    public static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    public static func typeErased(
        _ buffer: Buffer
    ) -> SignalOwnedBufferOfMaxAlignedc_void {
        SignalOwnedBufferOfMaxAlignedc_void(
            base: UnsafeMutableRawPointer(buffer.base),
            length: buffer.length,
            size_bytes: buffer.size_bytes,
        )
    }
}

internal enum FixedByteArrayHelper15: FixedByteArrayHelper {
    public typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    public static func count() -> Int {
        15
    }
    public static func emptyFfi() -> Ffi {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

internal enum FixedByteArrayHelper32: FixedByteArrayHelper {
    public typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    public static func count() -> Int {
        32
    }
    public static func emptyFfi() -> Ffi {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

internal enum FixedByteArrayHelper64: FixedByteArrayHelper {
    public typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    public static func count() -> Int {
        64
    }
    public static func emptyFfi() -> Ffi {
        (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    }
}

internal enum CopyBackupMediaOut {
    case item(BridgeCopyBackupMediaOutcome)
    case invalidDataInStream
    case credentialRejected
    case credentialRejectedWithoutAppropriateServerInfo
}

internal struct GetDevicesOut {
    var devices: [LinkedDeviceInternal]

}

internal enum MyRemoteDeriveEnum {
    case unit
    case tuple(Int32, Int32)
    case record(x: String, y: Int32)
}

internal struct MyRemoteDeriveStruct {
    var x: Int32
    var y: Int32

}

internal enum MySimpleTestEnum {
    case a
    case b
}

internal enum MyTestEnum {
    case unit
    case single(Int32)
    case singleNamed(x: Int32)
    case double(Int32, Int32)
    case record(personName: String, personAge: Int32, position: MyTestPoint, funStruct: MyTestStruct)
}

internal struct MyTestPoint {
    var _0: Int32
    var _1: Int32

    init(_ _0: Int32, _ _1: Int32, ) {
        self._0 = _0
        self._1 = _1

    }
    init(_0: Int32, _1: Int32, ) {
        self._0 = _0
        self._1 = _1

    }

}

internal struct MyTestStruct {
    var myNumericField: Int32
    var myStringField: String

}

internal struct RemoveDeviceArgs {
    var id: UInt8

}

internal enum RemoveDeviceOut {
    case success
}

internal struct ReserveUsernameHashArgs {
    var usernames: [Data]

}

internal enum ReserveUsernameHashOut {
    case success(Data)
    case usernameNotAvailable
}

internal struct SetDeviceNameArgs {
    var id: UInt8
    var encryptedName: Data

}

internal enum SetDeviceNameOut {
    case success
    case deviceNotFound
}

internal struct SetUsernameLinkArgs {
    var usernameCiphertext: Data
    var keepLinkHandle: Bool

}

internal enum SetUsernameLinkOut {
    case success(UUID)
    case usernameNotSet
}

internal struct TestStreamChunk {
    var chunk: [String]
    var termination: BulkPolledStreamTermination?

}

internal enum DerivedReturnConverterCopyBackupMediaOut: NiceReturnConverter {
    typealias NiceReturn = CopyBackupMediaOut
    typealias FfiReturn = SignalCopyBackupMediaOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalCopyBackupMediaOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalCopyBackupMediaOutFfiResultItem:
            let _0 = Result {
                try DerivedReturnConverterBridgeCopyBackupMediaOutcome.convertReturn(
                    consuming: ffiValue.item._0
                )
            }
            return CopyBackupMediaOut.item(try _0.get())
        case SignalCopyBackupMediaOutFfiResultInvalidDataInStream:
            return CopyBackupMediaOut.invalidDataInStream
        case SignalCopyBackupMediaOutFfiResultCredentialRejected:
            return CopyBackupMediaOut.credentialRejected
        case SignalCopyBackupMediaOutFfiResultCredentialRejectedWithoutAppropriateServerInfo:
            return CopyBackupMediaOut.credentialRejectedWithoutAppropriateServerInfo
        default:
            throw SignalError.internalError("Unexpected enum tag for CopyBackupMediaOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterGetDevicesOut: NiceReturnConverter {
    typealias NiceReturn = GetDevicesOut
    typealias FfiReturn = SignalGetDevicesOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalGetDevicesOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let devices = Result {
            try ArrayReturnConverter<
                DerivedReturnConverterLinkedDeviceInternal,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_DerivedReturnConverterLinkedDeviceInternal
            >.convertReturn(consuming: ffiValue.devices)
        }

        return GetDevicesOut(devices: try devices.get())
    }
}

internal enum DerivedReturnConverterMyRemoteDeriveEnum: NiceReturnConverter {
    typealias NiceReturn = MyRemoteDeriveEnum
    typealias FfiReturn = SignalMyRemoteDeriveEnumFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyRemoteDeriveEnumFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalMyRemoteDeriveEnumFfiResultUnit:
            return MyRemoteDeriveEnum.unit
        case SignalMyRemoteDeriveEnumFfiResultTuple:
            let _0 = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.tuple._0
                )
            }
            let _1 = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.tuple._1
                )
            }
            return MyRemoteDeriveEnum.tuple(try _0.get(), try _1.get())
        case SignalMyRemoteDeriveEnumFfiResultRecord:
            let x = Result {
                try StringConverter.convertReturn(
                    consuming: ffiValue.record.x
                )
            }
            let y = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.record.y
                )
            }
            return MyRemoteDeriveEnum.record(x: try x.get(), y: try y.get())
        default:
            throw SignalError.internalError("Unexpected enum tag for MyRemoteDeriveEnum: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterMyRemoteDeriveStruct: NiceReturnConverter {
    typealias NiceReturn = MyRemoteDeriveStruct
    typealias FfiReturn = SignalMyRemoteDeriveStructFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyRemoteDeriveStructFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let x = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.x) }
        let y = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.y) }

        return MyRemoteDeriveStruct(x: try x.get(), y: try y.get())
    }
}

internal enum DerivedReturnConverterMySimpleTestEnum: NiceReturnConverter {
    typealias NiceReturn = MySimpleTestEnum
    typealias FfiReturn = SignalMySimpleTestEnumFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMySimpleTestEnumFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalMySimpleTestEnumFfiResultA:
            return MySimpleTestEnum.a
        case SignalMySimpleTestEnumFfiResultB:
            return MySimpleTestEnum.b
        default:
            throw SignalError.internalError("Unexpected enum tag for MySimpleTestEnum: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterMyTestEnum: NiceReturnConverter {
    typealias NiceReturn = MyTestEnum
    typealias FfiReturn = SignalMyTestEnumFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyTestEnumFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalMyTestEnumFfiResultUnit:
            return MyTestEnum.unit
        case SignalMyTestEnumFfiResultSingle:
            let _0 = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.single._0
                )
            }
            return MyTestEnum.single(try _0.get())
        case SignalMyTestEnumFfiResultSingleNamed:
            let x = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.single_named.x
                )
            }
            return MyTestEnum.singleNamed(x: try x.get())
        case SignalMyTestEnumFfiResultDouble:
            let _0 = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.double_._0
                )
            }
            let _1 = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.double_._1
                )
            }
            return MyTestEnum.double(try _0.get(), try _1.get())
        case SignalMyTestEnumFfiResultRecord:
            let person_name = Result {
                try StringConverter.convertReturn(
                    consuming: ffiValue.record.person_name
                )
            }
            let person_age = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.record.person_age
                )
            }
            let position = Result {
                try DerivedReturnConverterMyTestPoint.convertReturn(
                    consuming: ffiValue.record.position
                )
            }
            let fun_struct = Result {
                try DerivedReturnConverterMyTestStruct.convertReturn(
                    consuming: ffiValue.record.fun_struct
                )
            }
            return MyTestEnum.record(
                personName: try person_name.get(),
                personAge: try person_age.get(),
                position: try position.get(),
                funStruct: try fun_struct.get()
            )
        default:
            throw SignalError.internalError("Unexpected enum tag for MyTestEnum: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterMyTestPoint: NiceReturnConverter {
    typealias NiceReturn = MyTestPoint
    typealias FfiReturn = SignalMyTestPointFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyTestPointFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let _0 = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue._0) }
        let _1 = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue._1) }

        return MyTestPoint(_0: try _0.get(), _1: try _1.get())
    }
}

internal enum DerivedReturnConverterMyTestStruct: NiceReturnConverter {
    typealias NiceReturn = MyTestStruct
    typealias FfiReturn = SignalMyTestStructFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyTestStructFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let my_numeric_field = Result {
            try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.my_numeric_field)
        }
        let my_string_field = Result { try StringConverter.convertReturn(consuming: ffiValue.my_string_field) }

        return MyTestStruct(myNumericField: try my_numeric_field.get(), myStringField: try my_string_field.get())
    }
}

internal enum DerivedReturnConverterRemoveDeviceArgs: NiceReturnConverter {
    typealias NiceReturn = RemoveDeviceArgs
    typealias FfiReturn = SignalRemoveDeviceArgsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalRemoveDeviceArgsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let id = Result { try IdentityConverter<UInt8>.convertReturn(consuming: ffiValue.id) }

        return RemoveDeviceArgs(id: try id.get())
    }
}

internal enum DerivedReturnConverterRemoveDeviceOut: NiceReturnConverter {
    typealias NiceReturn = RemoveDeviceOut
    typealias FfiReturn = SignalRemoveDeviceOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalRemoveDeviceOutFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalRemoveDeviceOutFfiResultSuccess:
            return RemoveDeviceOut.success
        default:
            throw SignalError.internalError("Unexpected enum tag for RemoveDeviceOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterReserveUsernameHashArgs: NiceReturnConverter {
    typealias NiceReturn = ReserveUsernameHashArgs
    typealias FfiReturn = SignalReserveUsernameHashArgsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalReserveUsernameHashArgsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let usernames = Result {
            try ArrayReturnConverter<
                FixedByteArrayConverter<FixedByteArrayHelper32>,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32
            >.convertReturn(consuming: ffiValue.usernames)
        }

        return ReserveUsernameHashArgs(usernames: try usernames.get())
    }
}

internal enum DerivedReturnConverterReserveUsernameHashOut: NiceReturnConverter {
    typealias NiceReturn = ReserveUsernameHashOut
    typealias FfiReturn = SignalReserveUsernameHashOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalReserveUsernameHashOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalReserveUsernameHashOutFfiResultSuccess:
            let _0 = Result {
                try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(
                    consuming: ffiValue.success._0
                )
            }
            return ReserveUsernameHashOut.success(try _0.get())
        case SignalReserveUsernameHashOutFfiResultUsernameNotAvailable:
            return ReserveUsernameHashOut.usernameNotAvailable
        default:
            throw SignalError.internalError("Unexpected enum tag for ReserveUsernameHashOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterSetDeviceNameArgs: NiceReturnConverter {
    typealias NiceReturn = SetDeviceNameArgs
    typealias FfiReturn = SignalSetDeviceNameArgsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalSetDeviceNameArgsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let id = Result { try IdentityConverter<UInt8>.convertReturn(consuming: ffiValue.id) }
        let encrypted_name = Result { try DataConverter.convertReturn(consuming: ffiValue.encrypted_name) }

        return SetDeviceNameArgs(id: try id.get(), encryptedName: try encrypted_name.get())
    }
}

internal enum DerivedReturnConverterSetDeviceNameOut: NiceReturnConverter {
    typealias NiceReturn = SetDeviceNameOut
    typealias FfiReturn = SignalSetDeviceNameOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalSetDeviceNameOutFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalSetDeviceNameOutFfiResultSuccess:
            return SetDeviceNameOut.success
        case SignalSetDeviceNameOutFfiResultDeviceNotFound:
            return SetDeviceNameOut.deviceNotFound
        default:
            throw SignalError.internalError("Unexpected enum tag for SetDeviceNameOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterSetUsernameLinkArgs: NiceReturnConverter {
    typealias NiceReturn = SetUsernameLinkArgs
    typealias FfiReturn = SignalSetUsernameLinkArgsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalSetUsernameLinkArgsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let username_ciphertext = Result { try DataConverter.convertReturn(consuming: ffiValue.username_ciphertext) }
        let keep_link_handle = Result {
            try IdentityConverter<Bool>.convertReturn(consuming: ffiValue.keep_link_handle)
        }

        return SetUsernameLinkArgs(
            usernameCiphertext: try username_ciphertext.get(),
            keepLinkHandle: try keep_link_handle.get()
        )
    }
}

internal enum DerivedReturnConverterSetUsernameLinkOut: NiceReturnConverter {
    typealias NiceReturn = SetUsernameLinkOut
    typealias FfiReturn = SignalSetUsernameLinkOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalSetUsernameLinkOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalSetUsernameLinkOutFfiResultSuccess:
            let _0 = Result {
                try UuidNiceConverter.convertReturn(
                    consuming: ffiValue.success._0
                )
            }
            return SetUsernameLinkOut.success(try _0.get())
        case SignalSetUsernameLinkOutFfiResultUsernameNotSet:
            return SetUsernameLinkOut.usernameNotSet
        default:
            throw SignalError.internalError("Unexpected enum tag for SetUsernameLinkOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterTestStreamChunk: NiceReturnConverter {
    typealias NiceReturn = TestStreamChunk
    typealias FfiReturn = SignalTestStreamChunkFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalTestStreamChunkFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let chunk = Result {
            try ArrayReturnConverter<
                StringConverter,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCStringPtr_StringConverter
            >.convertReturn(consuming: ffiValue.chunk)
        }
        let termination = Result {
            try BulkPolledStreamTerminationConverter.convertReturn(consuming: ffiValue.termination)
        }

        return TestStreamChunk(chunk: try chunk.get(), termination: try termination.get())
    }
}

internal enum MyRemoteDeriveEnumArgConverterKeepAlive {
    case unit(())
    case tuple((IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?))
    case record((StringConverter.KeepAlive?, IdentityConverter<Int32>.KeepAlive?))
}

internal enum DerivedArgConverterMyRemoteDeriveEnum: NiceArgConverter {
    typealias NiceArg = MyRemoteDeriveEnum
    typealias FfiArg = SignalMyRemoteDeriveEnumFfiArg
    typealias KeepAlive = MyRemoteDeriveEnumArgConverterKeepAlive
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .unit:
            return (
                SignalMyRemoteDeriveEnumFfiArg.init(
                    tag: SignalMyRemoteDeriveEnumFfiArgUnit,
                    .init(),
                ),
                nil,
            )

        case .tuple(
            let _0,
            let _1,
        ):

            let (_0_ffi, _0_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(_0)
            let (_1_ffi, _1_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(_1)

            let ffiStructArg = SignalMyRemoteDeriveEnumFfiArgSignalTuple_Body(_0: _0_ffi, _1: _1_ffi, )
            let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )? =
                (_0_keepalive != nil || _1_keepalive != nil || false) ? (_0_keepalive, _1_keepalive,) : nil

            return (
                SignalMyRemoteDeriveEnumFfiArg.init(
                    tag: SignalMyRemoteDeriveEnumFfiArgTuple,
                    .init(tuple: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .tuple($0) },
            )

        case .record(
            let x,
            let y,
        ):

            let (x_ffi, x_keepalive):
                (
                    StringConverter.FfiArg,
                    StringConverter.KeepAlive?,
                ) = StringConverter.convertArg(x)
            let (y_ffi, y_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(y)

            let ffiStructArg = SignalMyRemoteDeriveEnumFfiArgSignalRecord_Body(x: x_ffi, y: y_ffi, )
            let ffiStructKeepAlive: (StringConverter.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )? =
                (x_keepalive != nil || y_keepalive != nil || false) ? (x_keepalive, y_keepalive,) : nil

            return (
                SignalMyRemoteDeriveEnumFfiArg.init(
                    tag: SignalMyRemoteDeriveEnumFfiArgRecord,
                    .init(record: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .record($0) },
            )

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .unit:
            return try niceThunk(
                SignalMyRemoteDeriveEnumFfiArg.init(
                    tag: SignalMyRemoteDeriveEnumFfiArgUnit,
                    .init(),
                )
            )

        case .tuple(
            let _0,
            let _1,
        ):

            return try IdentityConverter<Int32>.convertArgBorrowed(_0) {
                ffi__0 in
                return try IdentityConverter<Int32>.convertArgBorrowed(_1) {
                    ffi__1 in

                    return try niceThunk(
                        SignalMyRemoteDeriveEnumFfiArg.init(
                            tag: SignalMyRemoteDeriveEnumFfiArgTuple,
                            .init(
                                tuple:
                                    SignalMyRemoteDeriveEnumFfiArgSignalTuple_Body(
                                        _0: ffi__0,
                                        _1: ffi__1,
                                    )
                            ),
                        )
                    )

                }
            }

        case .record(
            let x,
            let y,
        ):

            return try StringConverter.convertArgBorrowed(x) {
                ffi_x in
                return try IdentityConverter<Int32>.convertArgBorrowed(y) {
                    ffi_y in

                    return try niceThunk(
                        SignalMyRemoteDeriveEnumFfiArg.init(
                            tag: SignalMyRemoteDeriveEnumFfiArgRecord,
                            .init(
                                record:
                                    SignalMyRemoteDeriveEnumFfiArgSignalRecord_Body(
                                        x: ffi_x,
                                        y: ffi_y,
                                    )
                            ),
                        )
                    )

                }
            }

        }
    }
}

internal enum DerivedArgConverterMyRemoteDeriveStruct: NiceArgConverter {
    typealias NiceArg = MyRemoteDeriveStruct
    typealias FfiArg = SignalMyRemoteDeriveStructFfiArg

    typealias KeepAlive = (IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        let x = niceArg.x
        let y = niceArg.y

        let (x_ffi, x_keepalive):
            (
                IdentityConverter<Int32>.FfiArg,
                IdentityConverter<Int32>.KeepAlive?,
            ) = IdentityConverter<Int32>.convertArg(x)
        let (y_ffi, y_keepalive):
            (
                IdentityConverter<Int32>.FfiArg,
                IdentityConverter<Int32>.KeepAlive?,
            ) = IdentityConverter<Int32>.convertArg(y)

        let ffiStructArg = FfiArg(x: x_ffi, y: y_ffi, )
        let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )? =
            (x_keepalive != nil || y_keepalive != nil || false) ? (x_keepalive, y_keepalive,) : nil

        return (ffiStructArg, ffiStructKeepAlive)
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        let x = niceArg.x
        let y = niceArg.y

        return try IdentityConverter<Int32>.convertArgBorrowed(x) {
            ffi_x in
            return try IdentityConverter<Int32>.convertArgBorrowed(y) {
                ffi_y in

                return try niceThunk(
                    FfiArg(
                        x: ffi_x,
                        y: ffi_y,
                    )
                )

            }
        }

    }
}

internal enum DerivedArgConverterMySimpleTestEnum: NiceArgConverter {
    typealias NiceArg = MySimpleTestEnum
    typealias FfiArg = SignalMySimpleTestEnumFfiArg
    typealias KeepAlive = ()
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .a:
            return (SignalMySimpleTestEnumFfiArgA, nil)

        case .b:
            return (SignalMySimpleTestEnumFfiArgB, nil)

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .a:
            return try niceThunk(SignalMySimpleTestEnumFfiArgA)

        case .b:
            return try niceThunk(SignalMySimpleTestEnumFfiArgB)

        }
    }
}

internal enum MyTestEnumArgConverterKeepAlive {
    case unit(())
    case single((IdentityConverter<Int32>.KeepAlive?))
    case singleNamed((IdentityConverter<Int32>.KeepAlive?))
    case double((IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?))
    case record(
        (
            StringConverter.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, DerivedArgConverterMyTestPoint.KeepAlive?,
            DerivedArgConverterMyTestStruct.KeepAlive?
        )
    )
}

internal enum DerivedArgConverterMyTestEnum: NiceArgConverter {
    typealias NiceArg = MyTestEnum
    typealias FfiArg = SignalMyTestEnumFfiArg
    typealias KeepAlive = MyTestEnumArgConverterKeepAlive
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .unit:
            return (
                SignalMyTestEnumFfiArg.init(
                    tag: SignalMyTestEnumFfiArgUnit,
                    .init(),
                ),
                nil,
            )

        case .single(
            let _0,
        ):

            let (_0_ffi, _0_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(_0)

            let ffiStructArg = SignalMyTestEnumFfiArgSignalSingle_Body(_0: _0_ffi, )
            let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, )? =
                (_0_keepalive != nil || false) ? (_0_keepalive,) : nil

            return (
                SignalMyTestEnumFfiArg.init(
                    tag: SignalMyTestEnumFfiArgSingle,
                    .init(single: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .single($0) },
            )

        case .singleNamed(
            let x,
        ):

            let (x_ffi, x_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(x)

            let ffiStructArg = SignalMyTestEnumFfiArgSignalSingleNamed_Body(x: x_ffi, )
            let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, )? =
                (x_keepalive != nil || false) ? (x_keepalive,) : nil

            return (
                SignalMyTestEnumFfiArg.init(
                    tag: SignalMyTestEnumFfiArgSingleNamed,
                    .init(single_named: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .singleNamed($0) },
            )

        case .double(
            let _0,
            let _1,
        ):

            let (_0_ffi, _0_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(_0)
            let (_1_ffi, _1_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(_1)

            let ffiStructArg = SignalMyTestEnumFfiArgSignalDouble_Body(_0: _0_ffi, _1: _1_ffi, )
            let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )? =
                (_0_keepalive != nil || _1_keepalive != nil || false) ? (_0_keepalive, _1_keepalive,) : nil

            return (
                SignalMyTestEnumFfiArg.init(
                    tag: SignalMyTestEnumFfiArgDouble,
                    .init(double_: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .double($0) },
            )

        case .record(
            personName: let person_name,
            personAge: let person_age,
            let position,
            funStruct: let fun_struct,
        ):

            let (person_name_ffi, person_name_keepalive):
                (
                    StringConverter.FfiArg,
                    StringConverter.KeepAlive?,
                ) = StringConverter.convertArg(person_name)
            let (person_age_ffi, person_age_keepalive):
                (
                    IdentityConverter<Int32>.FfiArg,
                    IdentityConverter<Int32>.KeepAlive?,
                ) = IdentityConverter<Int32>.convertArg(person_age)
            let (position_ffi, position_keepalive):
                (
                    DerivedArgConverterMyTestPoint.FfiArg,
                    DerivedArgConverterMyTestPoint.KeepAlive?,
                ) = DerivedArgConverterMyTestPoint.convertArg(position)
            let (fun_struct_ffi, fun_struct_keepalive):
                (
                    DerivedArgConverterMyTestStruct.FfiArg,
                    DerivedArgConverterMyTestStruct.KeepAlive?,
                ) = DerivedArgConverterMyTestStruct.convertArg(fun_struct)

            let ffiStructArg = SignalMyTestEnumFfiArgSignalRecord_Body(
                person_name: person_name_ffi,
                person_age: person_age_ffi,
                position: position_ffi,
                fun_struct: fun_struct_ffi,
            )
            let ffiStructKeepAlive:
                (
                    StringConverter.KeepAlive?, IdentityConverter<Int32>.KeepAlive?,
                    DerivedArgConverterMyTestPoint.KeepAlive?, DerivedArgConverterMyTestStruct.KeepAlive?,
                )? =
                    (person_name_keepalive != nil || person_age_keepalive != nil || position_keepalive != nil
                        || fun_struct_keepalive != nil || false)
                    ? (person_name_keepalive, person_age_keepalive, position_keepalive, fun_struct_keepalive,) : nil

            return (
                SignalMyTestEnumFfiArg.init(
                    tag: SignalMyTestEnumFfiArgRecord,
                    .init(record: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .record($0) },
            )

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .unit:
            return try niceThunk(
                SignalMyTestEnumFfiArg.init(
                    tag: SignalMyTestEnumFfiArgUnit,
                    .init(),
                )
            )

        case .single(
            let _0,
        ):

            return try IdentityConverter<Int32>.convertArgBorrowed(_0) {
                ffi__0 in

                return try niceThunk(
                    SignalMyTestEnumFfiArg.init(
                        tag: SignalMyTestEnumFfiArgSingle,
                        .init(
                            single:
                                SignalMyTestEnumFfiArgSignalSingle_Body(
                                    _0: ffi__0,
                                )
                        ),
                    )
                )

            }

        case .singleNamed(
            let x,
        ):

            return try IdentityConverter<Int32>.convertArgBorrowed(x) {
                ffi_x in

                return try niceThunk(
                    SignalMyTestEnumFfiArg.init(
                        tag: SignalMyTestEnumFfiArgSingleNamed,
                        .init(
                            single_named:
                                SignalMyTestEnumFfiArgSignalSingleNamed_Body(
                                    x: ffi_x,
                                )
                        ),
                    )
                )

            }

        case .double(
            let _0,
            let _1,
        ):

            return try IdentityConverter<Int32>.convertArgBorrowed(_0) {
                ffi__0 in
                return try IdentityConverter<Int32>.convertArgBorrowed(_1) {
                    ffi__1 in

                    return try niceThunk(
                        SignalMyTestEnumFfiArg.init(
                            tag: SignalMyTestEnumFfiArgDouble,
                            .init(
                                double_:
                                    SignalMyTestEnumFfiArgSignalDouble_Body(
                                        _0: ffi__0,
                                        _1: ffi__1,
                                    )
                            ),
                        )
                    )

                }
            }

        case .record(
            personName: let person_name,
            personAge: let person_age,
            let position,
            funStruct: let fun_struct,
        ):

            return try StringConverter.convertArgBorrowed(person_name) {
                ffi_person_name in
                return try IdentityConverter<Int32>.convertArgBorrowed(person_age) {
                    ffi_person_age in
                    return try DerivedArgConverterMyTestPoint.convertArgBorrowed(position) {
                        ffi_position in
                        return try DerivedArgConverterMyTestStruct.convertArgBorrowed(fun_struct) {
                            ffi_fun_struct in

                            return try niceThunk(
                                SignalMyTestEnumFfiArg.init(
                                    tag: SignalMyTestEnumFfiArgRecord,
                                    .init(
                                        record:
                                            SignalMyTestEnumFfiArgSignalRecord_Body(
                                                person_name: ffi_person_name,
                                                person_age: ffi_person_age,
                                                position: ffi_position,
                                                fun_struct: ffi_fun_struct,
                                            )
                                    ),
                                )
                            )

                        }
                    }
                }
            }

        }
    }
}

internal enum DerivedArgConverterMyTestPoint: NiceArgConverter {
    typealias NiceArg = MyTestPoint
    typealias FfiArg = SignalMyTestPointFfiArg

    typealias KeepAlive = (IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        let _0 = niceArg._0
        let _1 = niceArg._1

        let (_0_ffi, _0_keepalive):
            (
                IdentityConverter<Int32>.FfiArg,
                IdentityConverter<Int32>.KeepAlive?,
            ) = IdentityConverter<Int32>.convertArg(_0)
        let (_1_ffi, _1_keepalive):
            (
                IdentityConverter<Int32>.FfiArg,
                IdentityConverter<Int32>.KeepAlive?,
            ) = IdentityConverter<Int32>.convertArg(_1)

        let ffiStructArg = FfiArg(_0: _0_ffi, _1: _1_ffi, )
        let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )? =
            (_0_keepalive != nil || _1_keepalive != nil || false) ? (_0_keepalive, _1_keepalive,) : nil

        return (ffiStructArg, ffiStructKeepAlive)
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        let _0 = niceArg._0
        let _1 = niceArg._1

        return try IdentityConverter<Int32>.convertArgBorrowed(_0) {
            ffi__0 in
            return try IdentityConverter<Int32>.convertArgBorrowed(_1) {
                ffi__1 in

                return try niceThunk(
                    FfiArg(
                        _0: ffi__0,
                        _1: ffi__1,
                    )
                )

            }
        }

    }
}

internal enum DerivedArgConverterMyTestStruct: NiceArgConverter {
    typealias NiceArg = MyTestStruct
    typealias FfiArg = SignalMyTestStructFfiArg

    typealias KeepAlive = (IdentityConverter<Int32>.KeepAlive?, StringConverter.KeepAlive?, )
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        let my_numeric_field = niceArg.myNumericField
        let my_string_field = niceArg.myStringField

        let (my_numeric_field_ffi, my_numeric_field_keepalive):
            (
                IdentityConverter<Int32>.FfiArg,
                IdentityConverter<Int32>.KeepAlive?,
            ) = IdentityConverter<Int32>.convertArg(my_numeric_field)
        let (my_string_field_ffi, my_string_field_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(my_string_field)

        let ffiStructArg = FfiArg(my_numeric_field: my_numeric_field_ffi, my_string_field: my_string_field_ffi, )
        let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, StringConverter.KeepAlive?, )? =
            (my_numeric_field_keepalive != nil || my_string_field_keepalive != nil || false)
            ? (my_numeric_field_keepalive, my_string_field_keepalive,) : nil

        return (ffiStructArg, ffiStructKeepAlive)
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        let my_numeric_field = niceArg.myNumericField
        let my_string_field = niceArg.myStringField

        return try IdentityConverter<Int32>.convertArgBorrowed(my_numeric_field) {
            ffi_my_numeric_field in
            return try StringConverter.convertArgBorrowed(my_string_field) {
                ffi_my_string_field in

                return try niceThunk(
                    FfiArg(
                        my_numeric_field: ffi_my_numeric_field,
                        my_string_field: ffi_my_string_field,
                    )
                )

            }
        }

    }
}

internal enum NativeTestingNice {
    internal static func TESTING_ClearPushTokenTests() throws -> [GrpcTestCase<Void, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_clear_push_token_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_CopyBackupMediaTests() throws -> [GrpcTestCase<
        [BridgeCopyBackupMediaItem], [CopyBackupMediaOut]
    >] {
        var rawOutput = GrpcTestCaseVecConverter<
            ArrayReturnConverter<
                DerivedReturnConverterBridgeCopyBackupMediaItem,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult_DerivedReturnConverterBridgeCopyBackupMediaItem
            >,
            ArrayReturnConverter<
                DerivedReturnConverterCopyBackupMediaOut,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCopyBackupMediaOutFfiResult_DerivedReturnConverterCopyBackupMediaOut
            >
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_copy_backup_media_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<
            ArrayReturnConverter<
                DerivedReturnConverterBridgeCopyBackupMediaItem,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult_DerivedReturnConverterBridgeCopyBackupMediaItem
            >,
            ArrayReturnConverter<
                DerivedReturnConverterCopyBackupMediaOut,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCopyBackupMediaOutFfiResult_DerivedReturnConverterCopyBackupMediaOut
            >
        >.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_DeleteUsernameHashTests() throws -> [GrpcTestCase<Void, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_delete_username_hash_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_DeleteUsernameLinkTests() throws -> [GrpcTestCase<Void, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_delete_username_link_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_GetDevicesTests() throws -> [GrpcTestCase<Void, GetDevicesOut>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetDevicesOut>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_get_devices_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetDevicesOut>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func TESTING_MyRemoteDeriveEnum_identity(
        x: MyRemoteDeriveEnum,
    ) throws -> MyRemoteDeriveEnum {
        try DerivedArgConverterMyRemoteDeriveEnum.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyRemoteDeriveEnum.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_remote_derive_enum_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyRemoteDeriveEnum.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyRemoteDeriveStruct_identity(
        x: MyRemoteDeriveStruct,
    ) throws -> MyRemoteDeriveStruct {
        try DerivedArgConverterMyRemoteDeriveStruct.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyRemoteDeriveStruct.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_remote_derive_struct_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyRemoteDeriveStruct.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MySimpleTestEnum_BridgeVec_identity(
        x: [MySimpleTestEnum],
    ) throws -> [MySimpleTestEnum] {
        try ArrayArgConverter<
            DerivedArgConverterMySimpleTestEnum,
            FfiBorrowedSliceConstructor_SignalBorrowedSliceOfMySimpleTestEnumFfiArg_DerivedArgConverterMySimpleTestEnum
        >.convertArgBorrowed(x) { xFfi in
            var rawOutput = ArrayReturnConverter<
                DerivedReturnConverterMySimpleTestEnum,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedMySimpleTestEnumFfiResult_DerivedReturnConverterMySimpleTestEnum
            >.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_simple_test_enum_bridge_vec_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try ArrayReturnConverter<
                DerivedReturnConverterMySimpleTestEnum,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedMySimpleTestEnumFfiResult_DerivedReturnConverterMySimpleTestEnum
            >.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MySimpleTestEnum_BridgeVec_to_string(
        x: [MySimpleTestEnum],
    ) throws -> String {
        try ArrayArgConverter<
            DerivedArgConverterMySimpleTestEnum,
            FfiBorrowedSliceConstructor_SignalBorrowedSliceOfMySimpleTestEnumFfiArg_DerivedArgConverterMySimpleTestEnum
        >.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_simple_test_enum_bridge_vec_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MySimpleTestEnum_identity(
        x: MySimpleTestEnum,
    ) throws -> MySimpleTestEnum {
        try DerivedArgConverterMySimpleTestEnum.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMySimpleTestEnum.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_simple_test_enum_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMySimpleTestEnum.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MySimpleTestEnum_to_string(
        x: MySimpleTestEnum,
    ) throws -> String {
        try DerivedArgConverterMySimpleTestEnum.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_simple_test_enum_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyTestEnum_identity(
        x: MyTestEnum,
    ) throws -> MyTestEnum {
        try DerivedArgConverterMyTestEnum.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyTestEnum.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_test_enum_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyTestEnum.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyTestEnum_to_string(
        x: MyTestEnum,
    ) throws -> String {
        try DerivedArgConverterMyTestEnum.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_test_enum_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyTestPoint_identity(
        x: MyTestPoint,
    ) throws -> MyTestPoint {
        try DerivedArgConverterMyTestPoint.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyTestPoint.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_test_point_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyTestPoint.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyTestPoint_to_string(
        x: MyTestPoint,
    ) throws -> String {
        try DerivedArgConverterMyTestPoint.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_test_point_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyTestStruct_identity(
        x: MyTestStruct,
    ) throws -> MyTestStruct {
        try DerivedArgConverterMyTestStruct.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyTestStruct.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_test_struct_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyTestStruct.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyTestStruct_to_string(
        x: MyTestStruct,
    ) throws -> String {
        try DerivedArgConverterMyTestStruct.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_test_struct_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_RemoveDeviceTests() throws -> [GrpcTestCase<RemoveDeviceArgs, RemoveDeviceOut>] {
        var rawOutput = GrpcTestCaseVecConverter<
            DerivedReturnConverterRemoveDeviceArgs, DerivedReturnConverterRemoveDeviceOut
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_remove_device_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<
            DerivedReturnConverterRemoveDeviceArgs, DerivedReturnConverterRemoveDeviceOut
        >.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_ReserveUsernameHashTests() throws -> [GrpcTestCase<
        ReserveUsernameHashArgs, ReserveUsernameHashOut
    >] {
        var rawOutput = GrpcTestCaseVecConverter<
            DerivedReturnConverterReserveUsernameHashArgs, DerivedReturnConverterReserveUsernameHashOut
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_reserve_username_hash_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<
            DerivedReturnConverterReserveUsernameHashArgs, DerivedReturnConverterReserveUsernameHashOut
        >.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_ReturnIoError() throws -> Error {
        var rawOutput = ErrorConverter.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_return_io_error(
                &rawOutput,
            )
        )
        return try ErrorConverter.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_ReturnSomeIoError(
        present: Bool,
    ) throws -> Error? {
        try IdentityConverter<Bool>.convertArgBorrowed(present) { presentFfi in
            var rawOutput = OptionalErrorConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_return_some_io_error(
                    &rawOutput,
                    presentFfi,
                )
            )
            return try OptionalErrorConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_SetDeviceNameTests() throws -> [GrpcTestCase<SetDeviceNameArgs, SetDeviceNameOut>] {
        var rawOutput = GrpcTestCaseVecConverter<
            DerivedReturnConverterSetDeviceNameArgs, DerivedReturnConverterSetDeviceNameOut
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_set_device_name_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<
            DerivedReturnConverterSetDeviceNameArgs, DerivedReturnConverterSetDeviceNameOut
        >.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_SetPushTokenApnsTests() throws -> [GrpcTestCase<String, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<StringConverter, VoidConverter>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_set_push_token_apns_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<StringConverter, VoidConverter>.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_SetUsernameLinkTests() throws -> [GrpcTestCase<
        SetUsernameLinkArgs, SetUsernameLinkOut
    >] {
        var rawOutput = GrpcTestCaseVecConverter<
            DerivedReturnConverterSetUsernameLinkArgs, DerivedReturnConverterSetUsernameLinkOut
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_set_username_link_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<
            DerivedReturnConverterSetUsernameLinkArgs, DerivedReturnConverterSetUsernameLinkOut
        >.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_TestStreamChunk_return() throws -> TestStreamChunk {
        var rawOutput = DerivedReturnConverterTestStreamChunk.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_test_stream_chunk_return(
                &rawOutput,
            )
        )
        return try DerivedReturnConverterTestStreamChunk.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_TestingIntBox_Get(
        myIntBox my_int_box: TestingIntBox,
    ) throws -> Int32 {
        try BridgeHandleRefConverter<SignalMutPointerTestingIntBox, TestingIntBox>.convertArgBorrowed(my_int_box) {
            my_int_boxFfi in
            var rawOutput = IdentityConverter<Int32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_testing_int_box_get(
                    &rawOutput,
                    my_int_boxFfi,
                )
            )
            return try IdentityConverter<Int32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_TokioAsyncContext_FutureSuccessBytes(
        asyncContext: TokioAsyncContext,
        count: Int32,
    ) async throws -> Data {
        let rawOutput: DataConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                IdentityConverter<Int32>.convertArgBorrowed(count) { countFfi in
                    SignalFfi.signal_testing_tokio_async_context_future_success_bytes(
                        promiseFfi,
                        asyncContextFfi.const(),
                        countFfi,
                    )
                }
            }
        return try DataConverter.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_conversion_BridgeVecData32_identity(
        x: [Data],
    ) throws -> [Data] {
        try ArrayArgConverter<
            FixedByteArrayConverter<FixedByteArrayHelper32>,
            FfiBorrowedSliceConstructor_SignalBorrowedSliceOfc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32
        >.convertArgBorrowed(x) { xFfi in
            var rawOutput = ArrayReturnConverter<
                FixedByteArrayConverter<FixedByteArrayHelper32>,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32
            >.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bridge_vec_data32_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try ArrayReturnConverter<
                FixedByteArrayConverter<FixedByteArrayHelper32>,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32
            >.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_BridgeVecData32_to_string(
        x: [Data],
    ) throws -> String {
        try ArrayArgConverter<
            FixedByteArrayConverter<FixedByteArrayHelper32>,
            FfiBorrowedSliceConstructor_SignalBorrowedSliceOfc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32
        >.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bridge_vec_data32_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_BridgeVecString_identity(
        x: [String],
    ) throws -> [String] {
        try ArrayArgConverter<
            StringConverter, FfiBorrowedSliceConstructor_SignalBorrowedSliceOfCStringPtr_StringConverter
        >.convertArgBorrowed(x) { xFfi in
            var rawOutput = ArrayReturnConverter<
                StringConverter,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCStringPtr_StringConverter
            >.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bridge_vec_string_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try ArrayReturnConverter<
                StringConverter,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCStringPtr_StringConverter
            >.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_BridgeVecString_to_string(
        x: [String],
    ) throws -> String {
        try ArrayArgConverter<
            StringConverter, FfiBorrowedSliceConstructor_SignalBorrowedSliceOfCStringPtr_StringConverter
        >.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bridge_vec_string_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Data32_identity(
        x: Data,
    ) throws -> Data {
        try FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = FixedByteArrayConverter<FixedByteArrayHelper32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data32_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Data32_to_string(
        x: Data,
    ) throws -> String {
        try FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data32_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Data_VecU8_identity(
        x: Data,
    ) throws -> Data {
        try DataConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = DataConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data_vec_u8_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DataConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Data_VecU8_to_string(
        x: Data,
    ) throws -> String {
        try DataConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data_vec_u8_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Data_identity(
        x: Data,
    ) throws -> Data {
        try DataConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = DataConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DataConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Data_to_string(
        x: Data,
    ) throws -> String {
        try DataConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_DeviceId_identity(
        x: DeviceId,
    ) throws -> DeviceId {
        try DeviceIdConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = DeviceIdConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_device_id_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DeviceIdConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_DeviceId_to_string(
        x: DeviceId,
    ) throws -> String {
        try DeviceIdConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_device_id_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_ServiceId_identity(
        x: ServiceId,
    ) throws -> ServiceId {
        try ServiceIdConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = ServiceIdConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_service_id_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try ServiceIdConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_ServiceId_to_string(
        x: ServiceId,
    ) throws -> String {
        try ServiceIdConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_service_id_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Timestamp_identity(
        x: Date,
    ) throws -> Date {
        try TimestampConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = TimestampConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_timestamp_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try TimestampConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Timestamp_to_string(
        x: Date,
    ) throws -> String {
        try TimestampConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_timestamp_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Uuid_identity(
        x: UUID,
    ) throws -> UUID {
        try UuidNiceConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = UuidNiceConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_uuid_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try UuidNiceConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Uuid_to_string(
        x: UUID,
    ) throws -> String {
        try UuidNiceConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_uuid_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_bool_identity(
        x: Bool,
    ) throws -> Bool {
        try IdentityConverter<Bool>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<Bool>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bool_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<Bool>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_bool_to_string(
        x: Bool,
    ) throws -> String {
        try IdentityConverter<Bool>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bool_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_i32_identity(
        x: Int32,
    ) throws -> Int32 {
        try IdentityConverter<Int32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<Int32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_i32_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<Int32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_i32_to_string(
        x: Int32,
    ) throws -> String {
        try IdentityConverter<Int32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_i32_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_string_identity(
        x: String,
    ) throws -> String {
        try StringConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_string_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u16_identity(
        x: UInt16,
    ) throws -> UInt16 {
        try IdentityConverter<UInt16>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<UInt16>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u16_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<UInt16>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u16_to_string(
        x: UInt16,
    ) throws -> String {
        try IdentityConverter<UInt16>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u16_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u8_identity(
        x: UInt8,
    ) throws -> UInt8 {
        try IdentityConverter<UInt8>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<UInt8>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u8_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<UInt8>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u8_to_string(
        x: UInt8,
    ) throws -> String {
        try IdentityConverter<UInt8>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u8_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_forceEmitVecOfBridgeCopyBackupMediaOut() throws -> [CopyBackupMediaOut] {
        var rawOutput = ArrayReturnConverter<
            DerivedReturnConverterCopyBackupMediaOut,
            FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCopyBackupMediaOutFfiResult_DerivedReturnConverterCopyBackupMediaOut
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_force_emit_vec_of_bridge_copy_backup_media_out(
                &rawOutput,
            )
        )
        return try ArrayReturnConverter<
            DerivedReturnConverterCopyBackupMediaOut,
            FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCopyBackupMediaOutFfiResult_DerivedReturnConverterCopyBackupMediaOut
        >.convertReturn(consuming: rawOutput)

    }
}

#endif
