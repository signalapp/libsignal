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

extension SignalCPromiseRawPointer: SignalCPromise {

    public typealias Result = SignalType_ConstPointer_void?

    public init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalType_ConstPointer_void_SignalType_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    public var generic_complete:
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalType_ConstPointer_void_SignalType_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    public var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    public var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisei32: SignalCPromise {

    public typealias Result = Int32

    public init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_int32_t_SignalType_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    public var generic_complete:
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_int32_t_SignalType_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    public var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    public var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseTestStreamChunkFfiResult: SignalCPromise {

    public typealias Result = SignalTestStreamChunkFfiResult

    public init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalTestStreamChunkFfiResult_SignalType_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    public var generic_complete:
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalTestStreamChunkFfiResult_SignalType_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    public var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    public var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerOtherTestingHandleType: SignalCPromise {

    public typealias Result = SignalMutPointerOtherTestingHandleType

    public init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerOtherTestingHandleType_SignalType_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    public var generic_complete:
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerOtherTestingHandleType_SignalType_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    public var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    public var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerTestingHandleType: SignalCPromise {

    public typealias Result = SignalMutPointerTestingHandleType

    public init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerTestingHandleType_SignalType_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    public var generic_complete:
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerTestingHandleType_SignalType_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    public var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    public var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerFakeChatRemoteEnd: SignalCPromise {

    public typealias Result = SignalMutPointerFakeChatRemoteEnd

    public init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerFakeChatRemoteEnd_SignalType_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    public var generic_complete:
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerFakeChatRemoteEnd_SignalType_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    public var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    public var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOptionalPairOfMutPointerHttpRequestu64: SignalCPromise {

    public typealias Result = SignalOptionalPairOfMutPointerHttpRequestu64

    public init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOptionalPairOfMutPointerHttpRequestu64_SignalType_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    public var generic_complete:
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOptionalPairOfMutPointerHttpRequestu64_SignalType_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    public var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    public var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalOptionalOfOwnedBuffer: SignalOptionalOf {

    public typealias Contents = SignalOwnedBuffer

    public init(
        generic_present: CBool,
        generic_value: MaybeUninitOfOwnedBuffer,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    public var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    public var generic_value: MaybeUninitOfOwnedBuffer {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalPairOfi32CStringPtr: SignalPairOf {

    public typealias First = Int32

    public typealias Second = SignalCStringPtr?

    public init(
        generic_first: Int32,
        generic_second: SignalCStringPtr?,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    public var generic_first: Int32 {
        get { self.first }
        set { first = newValue }
    }

    public var generic_second: SignalCStringPtr? {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfu32u32: SignalPairOf {

    public typealias First = UInt32

    public typealias Second = UInt32

    public init(
        generic_first: UInt32,
        generic_second: UInt32,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    public var generic_first: UInt32 {
        get { self.first }
        set { first = newValue }
    }

    public var generic_second: UInt32 {
        get { self.second }
        set { second = newValue }
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

enum
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult_DerivedReturnConverterBridgeCopyBackupMediaItem:
        FfiOwnedBufferOfMaxAlignedProject
{
    public typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult
    public typealias Element = DerivedReturnConverterBridgeCopyBackupMediaItem.FfiReturn
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
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedDeleteBackupMediaOutFfiResult_DerivedReturnConverterDeleteBackupMediaOut:
        FfiOwnedBufferOfMaxAlignedProject
{
    public typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedDeleteBackupMediaOutFfiResult
    public typealias Element = DerivedReturnConverterDeleteBackupMediaOut.FfiReturn
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

internal enum DeleteBackupMediaOut {
    case item(BridgeDeleteBackupMediaItem)
    case invalidDataInStream
    case credentialRejected
    case credentialRejectedWithoutAppropriateServerInfo
}

internal enum GetCdnCredentialsOut {
    case success(BackupCdnCredentials)
    case credentialRejected
    case missingResponse
}

internal struct GetDevicesOut {
    var devices: [LinkedDevice]

}

internal enum GetMediaBackupInfoOut {
    case success(BridgeMediaBackupInfo)
    case credentialRejected
    case missingResponse
}

internal enum GetMessageBackupInfoOut {
    case success(BridgeMessageBackupInfo)
    case credentialRejected
    case missingResponse
}

internal enum GetSvrBCredentialsOut {
    case success(username: String, password: String)
    case credentialRejected
    case missingResponse
}

internal struct ListMediaArgs {
    var cursor: String?
    var limit: Int32

}

internal enum ListMediaOut {
    case page(ListMediaResponse)
    case malformedMediaId
    case credentialRejected
    case missingResponse
}

internal struct LookUpUsernameLinkArgs {
    var uuid: UUID
    var entropy: Data

}

internal enum LookUpUsernameLinkOut {
    case success(String)
    case notFound
    case linkDataTooShort
    case missingResponse
}

/*
// MyNiceTypeEnum

internal enum MyNiceTypeEnumNot {
    case unit
    case single(Int32)
}

*/

/*
// MyNiceTypeSimpleEnum

internal enum MyNiceTypeSimpleEnumNot {
    case a
    case b
}

*/

/*
// MyNiceTypeStruct

internal struct MyNiceTypeStructNot {
    var x: Int32
    var y: Int32

}

*/

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

internal enum SimpleBackupTestOut {
    case success
    case credentialRejected
    case missingResponse
}

internal struct TestStreamChunk {
    var chunk: [String]
    var termination: BulkPolledStreamTermination?

}

internal enum DerivedReturnConverterBridgeCopyBackupMediaItem: NiceReturnConverter {
    typealias NiceReturn = BridgeCopyBackupMediaItem
    typealias FfiReturn = SignalBridgeCopyBackupMediaItemFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeCopyBackupMediaItemFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let source_attachment_cdn = Result {
            try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.source_attachment_cdn)
        }
        let source_key = Result { try StringConverter.convertReturn(consuming: ffiValue.source_key) }
        let object_length = Result { try IdentityConverter<Int64>.convertReturn(consuming: ffiValue.object_length) }
        let media_id = Result {
            try FixedByteArrayConverter<FixedByteArrayHelper15>.convertReturn(consuming: ffiValue.media_id)
        }
        let encryption_key = Result {
            try FixedByteArrayConverter<FixedByteArrayHelper64>.convertReturn(consuming: ffiValue.encryption_key)
        }

        return BridgeCopyBackupMediaItem(
            sourceAttachmentCdn: try source_attachment_cdn.get(),
            sourceKey: try source_key.get(),
            objectLength: try object_length.get(),
            mediaId: try media_id.get(),
            encryptionKey: try encryption_key.get()
        )
    }
}

internal enum DerivedReturnConverterCallQualitySurveyInternal: NiceReturnConverter {
    typealias NiceReturn = CallQualitySurvey
    typealias FfiReturn = SignalCallQualitySurveyInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalCallQualitySurveyInternalFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let user_satisfied = Result { try IdentityConverter<Bool>.convertReturn(consuming: ffiValue.user_satisfied) }
        let call_quality_issues = Result {
            try ArrayReturnConverter<
                StringConverter,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedCStringPtr_StringConverter
            >.convertReturn(consuming: ffiValue.call_quality_issues)
        }
        let additional_issues_description = Result {
            try OptionalStringConverter.convertReturn(consuming: ffiValue.additional_issues_description)
        }
        let debug_log_url = Result { try OptionalStringConverter.convertReturn(consuming: ffiValue.debug_log_url) }
        let start_timestamp = Result { try TimestampConverter.convertReturn(consuming: ffiValue.start_timestamp) }
        let end_timestamp = Result { try TimestampConverter.convertReturn(consuming: ffiValue.end_timestamp) }
        let call_type = Result { try StringConverter.convertReturn(consuming: ffiValue.call_type) }
        let success = Result { try IdentityConverter<Bool>.convertReturn(consuming: ffiValue.success) }
        let call_end_reason = Result { try StringConverter.convertReturn(consuming: ffiValue.call_end_reason) }
        let connection_rtt_median = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.connection_rtt_median
            )
        }
        let audio_rtt_median = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.audio_rtt_median
            )
        }
        let video_rtt_median = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.video_rtt_median
            )
        }
        let audio_recv_jitter_median = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.audio_recv_jitter_median
            )
        }
        let video_recv_jitter_median = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.video_recv_jitter_median
            )
        }
        let audio_send_jitter_median = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.audio_send_jitter_median
            )
        }
        let video_send_jitter_median = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.video_send_jitter_median
            )
        }
        let audio_recv_packet_loss_fraction = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.audio_recv_packet_loss_fraction
            )
        }
        let video_recv_packet_loss_fraction = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.video_recv_packet_loss_fraction
            )
        }
        let audio_send_packet_loss_fraction = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.audio_send_packet_loss_fraction
            )
        }
        let video_send_packet_loss_fraction = Result {
            try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: ffiValue.video_send_packet_loss_fraction
            )
        }
        let call_telemetry = Result {
            try OptionalReturnConverter<DataConverter, SignalOptionalOfOwnedBuffer>.convertReturn(
                consuming: ffiValue.call_telemetry
            )
        }
        let call_id_hash = Result {
            try OptionalReturnConverter<DataConverter, SignalOptionalOfOwnedBuffer>.convertReturn(
                consuming: ffiValue.call_id_hash
            )
        }

        return CallQualitySurvey(
            userSatisfied: try user_satisfied.get(),
            callQualityIssues: try call_quality_issues.get(),
            additionalIssuesDescription: try additional_issues_description.get(),
            debugLogUrl: try debug_log_url.get(),
            startTimestamp: try start_timestamp.get(),
            endTimestamp: try end_timestamp.get(),
            callType: try call_type.get(),
            success: try success.get(),
            callEndReason: try call_end_reason.get(),
            connectionRttMedian: try connection_rtt_median.get(),
            audioRttMedian: try audio_rtt_median.get(),
            videoRttMedian: try video_rtt_median.get(),
            audioRecvJitterMedian: try audio_recv_jitter_median.get(),
            videoRecvJitterMedian: try video_recv_jitter_median.get(),
            audioSendJitterMedian: try audio_send_jitter_median.get(),
            videoSendJitterMedian: try video_send_jitter_median.get(),
            audioRecvPacketLossFraction: try audio_recv_packet_loss_fraction.get(),
            videoRecvPacketLossFraction: try video_recv_packet_loss_fraction.get(),
            audioSendPacketLossFraction: try audio_send_packet_loss_fraction.get(),
            videoSendPacketLossFraction: try video_send_packet_loss_fraction.get(),
            callTelemetry: try call_telemetry.get(),
            callIdHash: try call_id_hash.get()
        )
    }
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

internal enum DerivedReturnConverterDeleteBackupMediaOut: NiceReturnConverter {
    typealias NiceReturn = DeleteBackupMediaOut
    typealias FfiReturn = SignalDeleteBackupMediaOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalDeleteBackupMediaOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalDeleteBackupMediaOutFfiResultItem:
            let _0 = Result {
                try DerivedReturnConverterBridgeDeleteBackupMediaItem.convertReturn(
                    consuming: ffiValue.item._0
                )
            }
            return DeleteBackupMediaOut.item(try _0.get())
        case SignalDeleteBackupMediaOutFfiResultInvalidDataInStream:
            return DeleteBackupMediaOut.invalidDataInStream
        case SignalDeleteBackupMediaOutFfiResultCredentialRejected:
            return DeleteBackupMediaOut.credentialRejected
        case SignalDeleteBackupMediaOutFfiResultCredentialRejectedWithoutAppropriateServerInfo:
            return DeleteBackupMediaOut.credentialRejectedWithoutAppropriateServerInfo
        default:
            throw SignalError.internalError("Unexpected enum tag for DeleteBackupMediaOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterGetCdnCredentialsOut: NiceReturnConverter {
    typealias NiceReturn = GetCdnCredentialsOut
    typealias FfiReturn = SignalGetCdnCredentialsOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalGetCdnCredentialsOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalGetCdnCredentialsOutFfiResultSuccess:
            let _0 = Result {
                try BackupCdnCredentialsConverter.convertReturn(
                    consuming: ffiValue.success._0
                )
            }
            return GetCdnCredentialsOut.success(try _0.get())
        case SignalGetCdnCredentialsOutFfiResultCredentialRejected:
            return GetCdnCredentialsOut.credentialRejected
        case SignalGetCdnCredentialsOutFfiResultMissingResponse:
            return GetCdnCredentialsOut.missingResponse
        default:
            throw SignalError.internalError("Unexpected enum tag for GetCdnCredentialsOut: \(ffiTag)")
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

internal enum DerivedReturnConverterGetMediaBackupInfoOut: NiceReturnConverter {
    typealias NiceReturn = GetMediaBackupInfoOut
    typealias FfiReturn = SignalGetMediaBackupInfoOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalGetMediaBackupInfoOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalGetMediaBackupInfoOutFfiResultSuccess:
            let _0 = Result {
                try DerivedReturnConverterBridgeMediaBackupInfo.convertReturn(
                    consuming: ffiValue.success._0
                )
            }
            return GetMediaBackupInfoOut.success(try _0.get())
        case SignalGetMediaBackupInfoOutFfiResultCredentialRejected:
            return GetMediaBackupInfoOut.credentialRejected
        case SignalGetMediaBackupInfoOutFfiResultMissingResponse:
            return GetMediaBackupInfoOut.missingResponse
        default:
            throw SignalError.internalError("Unexpected enum tag for GetMediaBackupInfoOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterGetMessageBackupInfoOut: NiceReturnConverter {
    typealias NiceReturn = GetMessageBackupInfoOut
    typealias FfiReturn = SignalGetMessageBackupInfoOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalGetMessageBackupInfoOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalGetMessageBackupInfoOutFfiResultSuccess:
            let _0 = Result {
                try DerivedReturnConverterBridgeMessageBackupInfo.convertReturn(
                    consuming: ffiValue.success._0
                )
            }
            return GetMessageBackupInfoOut.success(try _0.get())
        case SignalGetMessageBackupInfoOutFfiResultCredentialRejected:
            return GetMessageBackupInfoOut.credentialRejected
        case SignalGetMessageBackupInfoOutFfiResultMissingResponse:
            return GetMessageBackupInfoOut.missingResponse
        default:
            throw SignalError.internalError("Unexpected enum tag for GetMessageBackupInfoOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterGetSvrBCredentialsOut: NiceReturnConverter {
    typealias NiceReturn = GetSvrBCredentialsOut
    typealias FfiReturn = SignalGetSvrBCredentialsOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalGetSvrBCredentialsOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalGetSvrBCredentialsOutFfiResultSuccess:
            let username = Result {
                try StringConverter.convertReturn(
                    consuming: ffiValue.success.username
                )
            }
            let password = Result {
                try StringConverter.convertReturn(
                    consuming: ffiValue.success.password
                )
            }
            return GetSvrBCredentialsOut.success(username: try username.get(), password: try password.get())
        case SignalGetSvrBCredentialsOutFfiResultCredentialRejected:
            return GetSvrBCredentialsOut.credentialRejected
        case SignalGetSvrBCredentialsOutFfiResultMissingResponse:
            return GetSvrBCredentialsOut.missingResponse
        default:
            throw SignalError.internalError("Unexpected enum tag for GetSvrBCredentialsOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterListMediaArgs: NiceReturnConverter {
    typealias NiceReturn = ListMediaArgs
    typealias FfiReturn = SignalListMediaArgsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalListMediaArgsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let cursor = Result { try OptionalStringConverter.convertReturn(consuming: ffiValue.cursor) }
        let limit = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.limit) }

        return ListMediaArgs(cursor: try cursor.get(), limit: try limit.get())
    }
}

internal enum DerivedReturnConverterListMediaOut: NiceReturnConverter {
    typealias NiceReturn = ListMediaOut
    typealias FfiReturn = SignalListMediaOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalListMediaOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalListMediaOutFfiResultPage:
            let _0 = Result {
                try DerivedReturnConverterListMediaResponse.convertReturn(
                    consuming: ffiValue.page._0
                )
            }
            return ListMediaOut.page(try _0.get())
        case SignalListMediaOutFfiResultMalformedMediaId:
            return ListMediaOut.malformedMediaId
        case SignalListMediaOutFfiResultCredentialRejected:
            return ListMediaOut.credentialRejected
        case SignalListMediaOutFfiResultMissingResponse:
            return ListMediaOut.missingResponse
        default:
            throw SignalError.internalError("Unexpected enum tag for ListMediaOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterLookUpUsernameLinkArgs: NiceReturnConverter {
    typealias NiceReturn = LookUpUsernameLinkArgs
    typealias FfiReturn = SignalLookUpUsernameLinkArgsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalLookUpUsernameLinkArgsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let uuid = Result { try UuidNiceConverter.convertReturn(consuming: ffiValue.uuid) }
        let entropy = Result {
            try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: ffiValue.entropy)
        }

        return LookUpUsernameLinkArgs(uuid: try uuid.get(), entropy: try entropy.get())
    }
}

internal enum DerivedReturnConverterLookUpUsernameLinkOut: NiceReturnConverter {
    typealias NiceReturn = LookUpUsernameLinkOut
    typealias FfiReturn = SignalLookUpUsernameLinkOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalLookUpUsernameLinkOutFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalLookUpUsernameLinkOutFfiResultSuccess:
            let _0 = Result {
                try StringConverter.convertReturn(
                    consuming: ffiValue.success._0
                )
            }
            return LookUpUsernameLinkOut.success(try _0.get())
        case SignalLookUpUsernameLinkOutFfiResultNotFound:
            return LookUpUsernameLinkOut.notFound
        case SignalLookUpUsernameLinkOutFfiResultLinkDataTooShort:
            return LookUpUsernameLinkOut.linkDataTooShort
        case SignalLookUpUsernameLinkOutFfiResultMissingResponse:
            return LookUpUsernameLinkOut.missingResponse
        default:
            throw SignalError.internalError("Unexpected enum tag for LookUpUsernameLinkOut: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterMyNiceTypeEnumNot: NiceReturnConverter {
    typealias NiceReturn = MyNiceTypeEnum
    typealias FfiReturn = SignalMyNiceTypeEnumNotFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyNiceTypeEnumNotFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalMyNiceTypeEnumNotFfiResultUnit:
            return MyNiceTypeEnum.unit
        case SignalMyNiceTypeEnumNotFfiResultSingle:
            let _0 = Result {
                try IdentityConverter<Int32>.convertReturn(
                    consuming: ffiValue.single._0
                )
            }
            return MyNiceTypeEnum.single(try _0.get())
        default:
            throw SignalError.internalError("Unexpected enum tag for MyNiceTypeEnumNot: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterMyNiceTypeSimpleEnumNot: NiceReturnConverter {
    typealias NiceReturn = MyNiceTypeSimpleEnum
    typealias FfiReturn = SignalMyNiceTypeSimpleEnumNotFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyNiceTypeSimpleEnumNotFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalMyNiceTypeSimpleEnumNotFfiResultA:
            return MyNiceTypeSimpleEnum.a
        case SignalMyNiceTypeSimpleEnumNotFfiResultB:
            return MyNiceTypeSimpleEnum.b
        default:
            throw SignalError.internalError("Unexpected enum tag for MyNiceTypeSimpleEnumNot: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterMyNiceTypeStructNot: NiceReturnConverter {
    typealias NiceReturn = MyNiceTypeStruct
    typealias FfiReturn = SignalMyNiceTypeStructNotFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalMyNiceTypeStructNotFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let x = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.x) }
        let y = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.y) }

        return MyNiceTypeStruct(x: try x.get(), y: try y.get())
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

internal enum DerivedReturnConverterSimpleBackupTestOut: NiceReturnConverter {
    typealias NiceReturn = SimpleBackupTestOut
    typealias FfiReturn = SignalSimpleBackupTestOutFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalSimpleBackupTestOutFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalSimpleBackupTestOutFfiResultSuccess:
            return SimpleBackupTestOut.success
        case SignalSimpleBackupTestOutFfiResultCredentialRejected:
            return SimpleBackupTestOut.credentialRejected
        case SignalSimpleBackupTestOutFfiResultMissingResponse:
            return SimpleBackupTestOut.missingResponse
        default:
            throw SignalError.internalError("Unexpected enum tag for SimpleBackupTestOut: \(ffiTag)")
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

internal enum MyNiceTypeEnumNotArgConverterKeepAlive {
    case unit(())
    case single((IdentityConverter<Int32>.KeepAlive?))
}

internal enum DerivedArgConverterMyNiceTypeEnumNot: NiceArgConverter {
    typealias NiceArg = MyNiceTypeEnum
    typealias FfiArg = SignalMyNiceTypeEnumNotFfiArg
    typealias KeepAlive = MyNiceTypeEnumNotArgConverterKeepAlive
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .unit:
            return (
                SignalMyNiceTypeEnumNotFfiArg.init(
                    tag: SignalMyNiceTypeEnumNotFfiArgUnit,
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

            let ffiStructArg = SignalMyNiceTypeEnumNotFfiArgSignalSingle_Body(_0: _0_ffi, )
            let ffiStructKeepAlive: (IdentityConverter<Int32>.KeepAlive?, )? =
                (_0_keepalive != nil || false)
                ? (_0_keepalive,)
                : nil

            return (
                SignalMyNiceTypeEnumNotFfiArg.init(
                    tag: SignalMyNiceTypeEnumNotFfiArgSingle,
                    .init(single: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .single($0) },
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
                SignalMyNiceTypeEnumNotFfiArg.init(
                    tag: SignalMyNiceTypeEnumNotFfiArgUnit,
                    .init(),
                )
            )

        case .single(
            let _0,
        ):

            return try IdentityConverter<Int32>.convertArgBorrowed(_0) {
                ffi__0 in

                return try niceThunk(
                    SignalMyNiceTypeEnumNotFfiArg.init(
                        tag: SignalMyNiceTypeEnumNotFfiArgSingle,
                        .init(
                            single:
                                SignalMyNiceTypeEnumNotFfiArgSignalSingle_Body(
                                    _0: ffi__0,
                                )
                        ),
                    )
                )

            }

        }
    }
}

internal enum DerivedArgConverterMyNiceTypeSimpleEnumNot: NiceArgConverter {
    typealias NiceArg = MyNiceTypeSimpleEnum
    typealias FfiArg = SignalMyNiceTypeSimpleEnumNotFfiArg
    typealias KeepAlive = ()
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .a:
            return (SignalMyNiceTypeSimpleEnumNotFfiArgA, nil)

        case .b:
            return (SignalMyNiceTypeSimpleEnumNotFfiArgB, nil)

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .a:
            return try niceThunk(SignalMyNiceTypeSimpleEnumNotFfiArgA)

        case .b:
            return try niceThunk(SignalMyNiceTypeSimpleEnumNotFfiArgB)

        }
    }
}

internal enum DerivedArgConverterMyNiceTypeStructNot: NiceArgConverter {
    typealias NiceArg = MyNiceTypeStruct
    typealias FfiArg = SignalMyNiceTypeStructNotFfiArg

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
            (x_keepalive != nil || y_keepalive != nil || false)
            ? (x_keepalive, y_keepalive,)
            : nil

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
                (_0_keepalive != nil || _1_keepalive != nil || false)
                ? (_0_keepalive, _1_keepalive,)
                : nil

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
                (x_keepalive != nil || y_keepalive != nil || false)
                ? (x_keepalive, y_keepalive,)
                : nil

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
            (x_keepalive != nil || y_keepalive != nil || false)
            ? (x_keepalive, y_keepalive,)
            : nil

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
                (_0_keepalive != nil || false)
                ? (_0_keepalive,)
                : nil

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
                (x_keepalive != nil || false)
                ? (x_keepalive,)
                : nil

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
                (_0_keepalive != nil || _1_keepalive != nil || false)
                ? (_0_keepalive, _1_keepalive,)
                : nil

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
                    ? (person_name_keepalive, person_age_keepalive, position_keepalive, fun_struct_keepalive,)
                    : nil

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
            (_0_keepalive != nil || _1_keepalive != nil || false)
            ? (_0_keepalive, _1_keepalive,)
            : nil

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
            ? (my_numeric_field_keepalive, my_string_field_keepalive,)
            : nil

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
    internal static func TESTING_BackupDeleteAllTests() throws -> [GrpcTestCase<Void, SimpleBackupTestOut>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterSimpleBackupTestOut>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_backup_delete_all_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterSimpleBackupTestOut>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func TESTING_BackupListMediaTests() throws -> [GrpcTestCase<ListMediaArgs, ListMediaOut>] {
        var rawOutput = GrpcTestCaseVecConverter<
            DerivedReturnConverterListMediaArgs, DerivedReturnConverterListMediaOut
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_backup_list_media_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<DerivedReturnConverterListMediaArgs, DerivedReturnConverterListMediaOut>
            .convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_BackupRefreshTests() throws -> [GrpcTestCase<Void, SimpleBackupTestOut>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterSimpleBackupTestOut>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_backup_refresh_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterSimpleBackupTestOut>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func TESTING_BackupSetPublicKeyTests() throws -> [GrpcTestCase<Void, SimpleBackupTestOut>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterSimpleBackupTestOut>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_backup_set_public_key_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterSimpleBackupTestOut>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func TESTING_ClearPushTokenTests() throws -> [GrpcTestCase<Void, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_clear_push_token_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_ClearRegistrationLockTests() throws -> [GrpcTestCase<Void, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, VoidConverter>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_clear_registration_lock_tests(
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
    internal static func TESTING_DeleteBackupMediaTests() throws -> [GrpcTestCase<
        [BridgeDeleteBackupMediaItem], [DeleteBackupMediaOut]
    >] {
        var rawOutput = GrpcTestCaseVecConverter<
            ArrayReturnConverter<
                DerivedReturnConverterBridgeDeleteBackupMediaItem,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeDeleteBackupMediaItemFfiResult_DerivedReturnConverterBridgeDeleteBackupMediaItem
            >,
            ArrayReturnConverter<
                DerivedReturnConverterDeleteBackupMediaOut,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedDeleteBackupMediaOutFfiResult_DerivedReturnConverterDeleteBackupMediaOut
            >
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_delete_backup_media_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<
            ArrayReturnConverter<
                DerivedReturnConverterBridgeDeleteBackupMediaItem,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeDeleteBackupMediaItemFfiResult_DerivedReturnConverterBridgeDeleteBackupMediaItem
            >,
            ArrayReturnConverter<
                DerivedReturnConverterDeleteBackupMediaOut,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedDeleteBackupMediaOutFfiResult_DerivedReturnConverterDeleteBackupMediaOut
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
    internal static func TESTING_GetBackupCdnCredentialsTests() throws -> [GrpcTestCase<Int32, GetCdnCredentialsOut>] {
        var rawOutput = GrpcTestCaseVecConverter<IdentityConverter<Int32>, DerivedReturnConverterGetCdnCredentialsOut>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_get_backup_cdn_credentials_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<IdentityConverter<Int32>, DerivedReturnConverterGetCdnCredentialsOut>
            .convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_GetBackupSvrBCredentialsTests() throws -> [GrpcTestCase<Void, GetSvrBCredentialsOut>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetSvrBCredentialsOut>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_get_backup_svr_b_credentials_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetSvrBCredentialsOut>.convertReturn(
            consuming: rawOutput
        )

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
    internal static func TESTING_GetMediaBackupInfoTests() throws -> [GrpcTestCase<Void, GetMediaBackupInfoOut>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetMediaBackupInfoOut>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_get_media_backup_info_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetMediaBackupInfoOut>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func TESTING_GetMessageBackupInfoTests() throws -> [GrpcTestCase<Void, GetMessageBackupInfoOut>] {
        var rawOutput = GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetMessageBackupInfoOut>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_get_message_backup_info_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<VoidConverter, DerivedReturnConverterGetMessageBackupInfoOut>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func TESTING_LookUpUsernameLinkTests() throws -> [GrpcTestCase<
        LookUpUsernameLinkArgs, LookUpUsernameLinkOut
    >] {
        var rawOutput = GrpcTestCaseVecConverter<
            DerivedReturnConverterLookUpUsernameLinkArgs, DerivedReturnConverterLookUpUsernameLinkOut
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_look_up_username_link_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<
            DerivedReturnConverterLookUpUsernameLinkArgs, DerivedReturnConverterLookUpUsernameLinkOut
        >.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_MyNiceTypeEnum_identity(
        x: MyNiceTypeEnum,
    ) throws -> MyNiceTypeEnum {
        try DerivedArgConverterMyNiceTypeEnumNot.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyNiceTypeEnumNot.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_nice_type_enum_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyNiceTypeEnumNot.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyNiceTypeEnum_to_string(
        x: MyNiceTypeEnum,
    ) throws -> String {
        try DerivedArgConverterMyNiceTypeEnumNot.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_nice_type_enum_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyNiceTypeSimpleEnum_identity(
        x: MyNiceTypeSimpleEnum,
    ) throws -> MyNiceTypeSimpleEnum {
        try DerivedArgConverterMyNiceTypeSimpleEnumNot.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyNiceTypeSimpleEnumNot.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_nice_type_simple_enum_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyNiceTypeSimpleEnumNot.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyNiceTypeSimpleEnum_to_string(
        x: MyNiceTypeSimpleEnum,
    ) throws -> String {
        try DerivedArgConverterMyNiceTypeSimpleEnumNot.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_nice_type_simple_enum_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyNiceTypeStruct_identity(
        x: MyNiceTypeStruct,
    ) throws -> MyNiceTypeStruct {
        try DerivedArgConverterMyNiceTypeStructNot.convertArgBorrowed(x) { xFfi in
            var rawOutput = DerivedReturnConverterMyNiceTypeStructNot.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_nice_type_struct_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DerivedReturnConverterMyNiceTypeStructNot.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_MyNiceTypeStruct_to_string(
        x: MyNiceTypeStruct,
    ) throws -> String {
        try DerivedArgConverterMyNiceTypeStructNot.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_my_nice_type_struct_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

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
    internal static func TESTING_SetDiscoverableByPhoneNumberTests() throws -> [GrpcTestCase<Bool, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<IdentityConverter<Bool>, VoidConverter>.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_set_discoverable_by_phone_number_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<IdentityConverter<Bool>, VoidConverter>.convertReturn(consuming: rawOutput)

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
    internal static func TESTING_SetRegistrationLockTests() throws -> [GrpcTestCase<Data, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<FixedByteArrayConverter<FixedByteArrayHelper32>, VoidConverter>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_set_registration_lock_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<FixedByteArrayConverter<FixedByteArrayHelper32>, VoidConverter>
            .convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_SetRegistrationRecoveryPasswordTests() throws -> [GrpcTestCase<Data, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<FixedByteArrayConverter<FixedByteArrayHelper32>, VoidConverter>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_set_registration_recovery_password_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<FixedByteArrayConverter<FixedByteArrayHelper32>, VoidConverter>
            .convertReturn(consuming: rawOutput)

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
    internal static func TESTING_SubmitCallQualitySurveyTests() throws -> [GrpcTestCase<CallQualitySurvey, Void>] {
        var rawOutput = GrpcTestCaseVecConverter<DerivedReturnConverterCallQualitySurveyInternal, VoidConverter>
            .emptyFfiReturn()
        try checkError(
            SignalFfi.signal_testing_submit_call_quality_survey_tests(
                &rawOutput,
            )
        )
        return try GrpcTestCaseVecConverter<DerivedReturnConverterCallQualitySurveyInternal, VoidConverter>
            .convertReturn(consuming: rawOutput)

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
    internal static func TESTING_conversion_Float_identity(
        x: Float,
    ) throws -> Float {
        try IdentityConverter<Float>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<Float>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_float_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<Float>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Float_to_string(
        x: Float,
    ) throws -> String {
        try IdentityConverter<Float>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_float_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_OptionalBytes_identity(
        x: Data?,
    ) throws -> Data? {
        try OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.convertArgBorrowed(x) { xFfi in
            var rawOutput = OptionalReturnConverter<DataConverter, SignalOptionalOfOwnedBuffer>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_optional_bytes_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try OptionalReturnConverter<DataConverter, SignalOptionalOfOwnedBuffer>.convertReturn(
                consuming: rawOutput
            )
        }

    }
    internal static func TESTING_conversion_OptionalBytes_to_string(
        x: Data?,
    ) throws -> String {
        try OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_optional_bytes_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_OptionalFloat_identity(
        x: Float?,
    ) throws -> Float? {
        try OptionalArgConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_optional_float_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try OptionalReturnConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertReturn(
                consuming: rawOutput
            )
        }

    }
    internal static func TESTING_conversion_OptionalFloat_to_string(
        x: Float?,
    ) throws -> String {
        try OptionalArgConverter<IdentityConverter<Float>, SignalOptionalOff32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_optional_float_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_OptionalString_identity(
        x: String?,
    ) throws -> String? {
        try OptionalStringConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = OptionalStringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_optional_string_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try OptionalStringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_OptionalString_to_string(
        x: String?,
    ) throws -> String {
        try OptionalStringConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_optional_string_to_string(
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
}

#endif
