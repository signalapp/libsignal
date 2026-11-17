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

import Foundation
import SignalFfi

extension SignalBorrowedSliceOfPtrToc_uchar32: SignalBorrowedSliceOf {

    typealias Element = SignalType_ConstPointer_FixedArray32_uint8_t?

    init(
        generic_base: SignalType_ConstPointer_ConstPointer_FixedArray32_uint8_t?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_ConstPointer_FixedArray32_uint8_t? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfCStringPtr: SignalBorrowedSliceOf {

    typealias Element = SignalCStringPtr?

    init(
        generic_base: SignalType_ConstPointer_SignalCStringPtr?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalCStringPtr? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfBuffers: SignalBorrowedSliceOf {

    typealias Element = SignalBorrowedBuffer

    init(
        generic_base: SignalType_ConstPointer_SignalBorrowedBuffer?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalBorrowedBuffer? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfConstPointerProtocolAddress: SignalBorrowedSliceOf {

    typealias Element = SignalConstPointerProtocolAddress

    init(
        generic_base: SignalType_ConstPointer_SignalConstPointerProtocolAddress?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalConstPointerProtocolAddress? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfConstPointerPublicKey: SignalBorrowedSliceOf {

    typealias Element = SignalConstPointerPublicKey

    init(
        generic_base: SignalType_ConstPointer_SignalConstPointerPublicKey?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalConstPointerPublicKey? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfConstPointerKyberPublicKey: SignalBorrowedSliceOf {

    typealias Element = SignalConstPointerKyberPublicKey

    init(
        generic_base: SignalType_ConstPointer_SignalConstPointerKyberPublicKey?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalConstPointerKyberPublicKey? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfConstPointerCiphertextMessage: SignalBorrowedSliceOf {

    typealias Element = SignalConstPointerCiphertextMessage

    init(
        generic_base: SignalType_ConstPointer_SignalConstPointerCiphertextMessage?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalConstPointerCiphertextMessage? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfConstPointerSessionRecord: SignalBorrowedSliceOf {

    typealias Element = SignalConstPointerSessionRecord

    init(
        generic_base: SignalType_ConstPointer_SignalConstPointerSessionRecord?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalConstPointerSessionRecord? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfBridgeCopyBackupMediaItemFfiArg: SignalBorrowedSliceOf {

    typealias Element = SignalBridgeCopyBackupMediaItemFfiArg

    init(
        generic_base: SignalType_ConstPointer_SignalBridgeCopyBackupMediaItemFfiArg?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalBridgeCopyBackupMediaItemFfiArg? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfBridgeDeleteBackupMediaItemFfiArg: SignalBorrowedSliceOf {

    typealias Element = SignalBridgeDeleteBackupMediaItemFfiArg

    init(
        generic_base: SignalType_ConstPointer_SignalBridgeDeleteBackupMediaItemFfiArg?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalBridgeDeleteBackupMediaItemFfiArg? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfDeviceCapabilityInternalFfiArg: SignalBorrowedSliceOf {

    typealias Element = SignalDeviceCapabilityInternalFfiArg

    init(
        generic_base: SignalType_ConstPointer_SignalDeviceCapabilityInternalFfiArg?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_SignalDeviceCapabilityInternalFfiArg? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfu32: SignalBorrowedSliceOf {

    typealias Element = UInt32

    init(
        generic_base: SignalType_ConstPointer_uint32_t?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_uint32_t? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedBuffer: SignalBorrowedSliceOf {

    typealias Element = UInt8

    init(
        generic_base: SignalType_ConstPointer_uint8_t?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_uint8_t? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalBorrowedSliceOfusize: SignalBorrowedSliceOf {

    typealias Element = size_t

    init(
        generic_base: SignalType_ConstPointer_size_t?,
        generic_length: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,

        )
    }

    var generic_base: SignalType_ConstPointer_size_t? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

}

extension SignalCPromisec_uchar153: SignalCPromise {

    typealias Result = SignalType_FixedArray153_uint8_t

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_FixedArray153_uint8_t_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_FixedArray153_uint8_t_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisec_uchar32: SignalCPromise {

    typealias Result = SignalType_FixedArray32_uint8_t

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_FixedArray32_uint8_t_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_FixedArray32_uint8_t_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisebool: SignalCPromise {

    typealias Result = CBool

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_bool_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete: SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_bool_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisei32: SignalCPromise {

    typealias Result = Int32

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_int32_t_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_int32_t_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseFfiCdsiLookupResponse: SignalCPromise {

    typealias Result = SignalFfiCdsiLookupResponse

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiCdsiLookupResponse_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiCdsiLookupResponse_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseFfiChatResponse: SignalCPromise {

    typealias Result = SignalFfiChatResponse

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiChatResponse_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiChatResponse_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseFfiCheckSvr2CredentialsResponse: SignalCPromise {

    typealias Result = SignalFfiCheckSvr2CredentialsResponse

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiCheckSvr2CredentialsResponse_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiCheckSvr2CredentialsResponse_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseFfiPreKeysResponse: SignalCPromise {

    typealias Result = SignalFfiPreKeysResponse

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiPreKeysResponse_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiPreKeysResponse_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseFfiUploadForm: SignalCPromise {

    typealias Result = SignalFfiUploadForm

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiUploadForm_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalFfiUploadForm_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerCdsiLookup: SignalCPromise {

    typealias Result = SignalMutPointerCdsiLookup

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerCdsiLookup_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerCdsiLookup_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerAuthenticatedChatConnection: SignalCPromise {

    typealias Result = SignalMutPointerAuthenticatedChatConnection

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerAuthenticatedChatConnection_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerAuthenticatedChatConnection_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerProvisioningChatConnection: SignalCPromise {

    typealias Result = SignalMutPointerProvisioningChatConnection

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerProvisioningChatConnection_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerProvisioningChatConnection_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerUnauthenticatedChatConnection: SignalCPromise {

    typealias Result = SignalMutPointerUnauthenticatedChatConnection

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerUnauthenticatedChatConnection_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerUnauthenticatedChatConnection_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerRegistrationService: SignalCPromise {

    typealias Result = SignalMutPointerRegistrationService

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerRegistrationService_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerRegistrationService_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerBackupRestoreResponse: SignalCPromise {

    typealias Result = SignalMutPointerBackupRestoreResponse

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerBackupRestoreResponse_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerBackupRestoreResponse_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerBackupStoreResponse: SignalCPromise {

    typealias Result = SignalMutPointerBackupStoreResponse

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerBackupStoreResponse_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerBackupStoreResponse_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseMutPointerRegisterAccountResponse: SignalCPromise {

    typealias Result = SignalMutPointerRegisterAccountResponse

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerRegisterAccountResponse_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalMutPointerRegisterAccountResponse_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOptionalOfCStringPtr: SignalCPromise {

    typealias Result = SignalOptionalOfCStringPtr

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfCStringPtr_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfCStringPtr_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOptionalOfPairOfCStringPtrc_uchar32: SignalCPromise {

    typealias Result = SignalOptionalOfPairOfCStringPtrc_uchar32

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfPairOfCStringPtrc_uchar32_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfPairOfCStringPtrc_uchar32_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOptionalOfUuid: SignalCPromise {

    typealias Result = SignalOptionalOfUuid

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfUuid_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfUuid_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOptionalOfFetchedProfileFfiResult: SignalCPromise {

    typealias Result = SignalOptionalOfFetchedProfileFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfFetchedProfileFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfFetchedProfileFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOptionalOfTaggedBadgesFfiResult: SignalCPromise {

    typealias Result = SignalOptionalOfTaggedBadgesFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfTaggedBadgesFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOptionalOfTaggedBadgesFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOwnedBufferOfc_uchar17: SignalCPromise {

    typealias Result = SignalOwnedBufferOfc_uchar17

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfc_uchar17_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfc_uchar17_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOwnedBuffer: SignalCPromise {

    typealias Result = SignalOwnedBuffer

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBuffer_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBuffer_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOwnedBufferOfMaxAlignedOwnedBuffer: SignalCPromise {

    typealias Result = SignalOwnedBufferOfMaxAlignedOwnedBuffer

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedOwnedBuffer_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedOwnedBuffer_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOwnedBufferOfMaxAlignedPairOfCStringPtrAuthCheckResultFfiResult: SignalCPromise {

    typealias Result = SignalOwnedBufferOfMaxAlignedPairOfCStringPtrAuthCheckResultFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedPairOfCStringPtrAuthCheckResultFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedPairOfCStringPtrAuthCheckResultFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOwnedBufferOfMaxAlignedBridgeConfirmedMfaKeyFfiResult: SignalCPromise {

    typealias Result = SignalOwnedBufferOfMaxAlignedBridgeConfirmedMfaKeyFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedBridgeConfirmedMfaKeyFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedBridgeConfirmedMfaKeyFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOwnedBufferOfMaxAlignedDeviceCapabilityInternalFfiResult: SignalCPromise {

    typealias Result = SignalOwnedBufferOfMaxAlignedDeviceCapabilityInternalFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedDeviceCapabilityInternalFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedDeviceCapabilityInternalFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult: SignalCPromise {

    typealias Result = SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisePairOfCStringPtrCStringPtr: SignalCPromise {

    typealias Result = SignalPairOfCStringPtrCStringPtr

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfCStringPtrCStringPtr_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfCStringPtrCStringPtr_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisePairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr: SignalCPromise {

    typealias Result = SignalPairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisePairOfOwnedBufferi64: SignalCPromise {

    typealias Result = SignalPairOfOwnedBufferi64

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfOwnedBufferi64_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfOwnedBufferi64_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromisePairOfOwnedBufferOwnedBuffer: SignalCPromise {

    typealias Result = SignalPairOfOwnedBufferOwnedBuffer

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfOwnedBufferOwnedBuffer_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalPairOfOwnedBufferOwnedBuffer_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseUuid: SignalCPromise {

    typealias Result = SignalUuid

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalUuid_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalUuid_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseBridgeAccountIdentityFfiResult: SignalCPromise {

    typealias Result = SignalBridgeAccountIdentityFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeAccountIdentityFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeAccountIdentityFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseBridgeMediaBackupInfoFfiResult: SignalCPromise {

    typealias Result = SignalBridgeMediaBackupInfoFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeMediaBackupInfoFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeMediaBackupInfoFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseBridgeMessageBackupInfoFfiResult: SignalCPromise {

    typealias Result = SignalBridgeMessageBackupInfoFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeMessageBackupInfoFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeMessageBackupInfoFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseBridgePendingTotpKeyFfiResult: SignalCPromise {

    typealias Result = SignalBridgePendingTotpKeyFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgePendingTotpKeyFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgePendingTotpKeyFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseBridgePreKeyCountsFfiResult: SignalCPromise {

    typealias Result = SignalBridgePreKeyCountsFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgePreKeyCountsFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgePreKeyCountsFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseBridgeWebAuthnCreateParametersFfiResult: SignalCPromise {

    typealias Result = SignalBridgeWebAuthnCreateParametersFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeWebAuthnCreateParametersFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalBridgeWebAuthnCreateParametersFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseCopyBackupMediaNextChunkFfiResult: SignalCPromise {

    typealias Result = SignalCopyBackupMediaNextChunkFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalCopyBackupMediaNextChunkFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalCopyBackupMediaNextChunkFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseDeleteBackupMediaNextChunkFfiResult: SignalCPromise {

    typealias Result = SignalDeleteBackupMediaNextChunkFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalDeleteBackupMediaNextChunkFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalDeleteBackupMediaNextChunkFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseAccountEntitlementsFfiResult: SignalCPromise {

    typealias Result = SignalAccountEntitlementsFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalAccountEntitlementsFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalAccountEntitlementsFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseCurrencyConversionsInternalFfiResult: SignalCPromise {

    typealias Result = SignalCurrencyConversionsInternalFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalCurrencyConversionsInternalFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalCurrencyConversionsInternalFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseGetStickerUploadFormsResponseFfiResult: SignalCPromise {

    typealias Result = SignalGetStickerUploadFormsResponseFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalGetStickerUploadFormsResponseFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalGetStickerUploadFormsResponseFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseListMediaResponseFfiResult: SignalCPromise {

    typealias Result = SignalListMediaResponseFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalListMediaResponseFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalListMediaResponseFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseS3UploadFormInternalFfiResult: SignalCPromise {

    typealias Result = SignalS3UploadFormInternalFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalS3UploadFormInternalFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalS3UploadFormInternalFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalCPromiseStartMfaVerificationResponseFfiResult: SignalCPromise {

    typealias Result = SignalStartMfaVerificationResponseFfiResult

    init(
        generic_complete:
            SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalStartMfaVerificationResponseFfiResult_ConstPointer_void?,
        generic_context: SignalType_ConstPointer_void?,
        generic_cancellation_id: UInt64,
    ) {
        self.init(
            complete: generic_complete,
            context: generic_context,
            cancellation_id: generic_cancellation_id,

        )
    }

    var generic_complete:
        SignalType_FunctionPointer_void_MutPointer_SignalFfiError_ConstPointer_SignalStartMfaVerificationResponseFfiResult_ConstPointer_void?
    {
        get { self.complete }
        set { complete = newValue }
    }

    var generic_context: SignalType_ConstPointer_void? {
        get { self.context }
        set { context = newValue }
    }

    var generic_cancellation_id: UInt64 {
        get { self.cancellation_id }
        set { cancellation_id = newValue }
    }

}

extension SignalOptionalOfPtrToc_uchar64: SignalOptionalOf {

    typealias Contents = SignalType_ConstPointer_FixedArray64_uint8_t?

    init(
        generic_present: CBool,
        generic_value: SignalType_ConstPointer_FixedArray64_uint8_t?,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalType_ConstPointer_FixedArray64_uint8_t? {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfCStringPtr: SignalOptionalOf {

    typealias Contents = SignalCStringPtr?

    init(
        generic_present: CBool,
        generic_value: SignalCStringPtr?,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalCStringPtr? {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfc_uchar10: SignalOptionalOf {

    typealias Contents = SignalType_FixedArray10_uint8_t

    init(
        generic_present: CBool,
        generic_value: SignalType_FixedArray10_uint8_t,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalType_FixedArray10_uint8_t {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfc_uchar17: SignalOptionalOf {

    typealias Contents = SignalType_FixedArray17_uint8_t

    init(
        generic_present: CBool,
        generic_value: SignalType_FixedArray17_uint8_t,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalType_FixedArray17_uint8_t {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfc_uchar32: SignalOptionalOf {

    typealias Contents = SignalType_FixedArray32_uint8_t

    init(
        generic_present: CBool,
        generic_value: SignalType_FixedArray32_uint8_t,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalType_FixedArray32_uint8_t {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfc_uchar64: SignalOptionalOf {

    typealias Contents = SignalType_FixedArray64_uint8_t

    init(
        generic_present: CBool,
        generic_value: SignalType_FixedArray64_uint8_t,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalType_FixedArray64_uint8_t {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfbool: SignalOptionalOf {

    typealias Contents = CBool

    init(
        generic_present: CBool,
        generic_value: CBool,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: CBool {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOff32: SignalOptionalOf {

    typealias Contents = Float

    init(
        generic_present: CBool,
        generic_value: Float,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: Float {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfBorrowedBuffer: SignalOptionalOf {

    typealias Contents = SignalBorrowedBuffer

    init(
        generic_present: CBool,
        generic_value: SignalBorrowedBuffer,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalBorrowedBuffer {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfOwnedBuffer: SignalOptionalOf {

    typealias Contents = SignalOwnedBuffer

    init(
        generic_present: CBool,
        generic_value: SignalOwnedBuffer,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalOwnedBuffer {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfPairOfCStringPtrc_uchar32: SignalOptionalOf {

    typealias Contents = SignalPairOfCStringPtrc_uchar32

    init(
        generic_present: CBool,
        generic_value: SignalPairOfCStringPtrc_uchar32,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalPairOfCStringPtrc_uchar32 {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfUuid: SignalOptionalOf {

    typealias Contents = SignalUuid

    init(
        generic_present: CBool,
        generic_value: SignalUuid,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalUuid {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfBackupEntitlementFfiResult: SignalOptionalOf {

    typealias Contents = SignalBackupEntitlementFfiResult

    init(
        generic_present: CBool,
        generic_value: SignalBackupEntitlementFfiResult,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalBackupEntitlementFfiResult {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfBridgeWebAuthnAuthenticationParametersFfiResult: SignalOptionalOf {

    typealias Contents = SignalBridgeWebAuthnAuthenticationParametersFfiResult

    init(
        generic_present: CBool,
        generic_value: SignalBridgeWebAuthnAuthenticationParametersFfiResult,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalBridgeWebAuthnAuthenticationParametersFfiResult {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfChargeFailureFfiResult: SignalOptionalOf {

    typealias Contents = SignalChargeFailureFfiResult

    init(
        generic_present: CBool,
        generic_value: SignalChargeFailureFfiResult,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalChargeFailureFfiResult {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfFetchedProfileFfiResult: SignalOptionalOf {

    typealias Contents = SignalFetchedProfileFfiResult

    init(
        generic_present: CBool,
        generic_value: SignalFetchedProfileFfiResult,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalFetchedProfileFfiResult {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOptionalOfTaggedBadgesFfiResult: SignalOptionalOf {

    typealias Contents = SignalTaggedBadgesFfiResult

    init(
        generic_present: CBool,
        generic_value: SignalTaggedBadgesFfiResult,
    ) {
        self.init(
            present: generic_present,
            value: generic_value,

        )
    }

    var generic_present: CBool {
        get { self.present }
        set { present = newValue }
    }

    var generic_value: SignalTaggedBadgesFfiResult {
        get { self.value }
        set { value = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedCStringPtr: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalCStringPtr?

    init(
        generic_base: SignalType_MutPointer_SignalCStringPtr?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalCStringPtr? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedi32: SignalOwnedBufferOfMaxAligned {

    typealias Element = Int32

    init(
        generic_base: SignalType_MutPointer_int32_t?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_int32_t? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedOwnedBuffer: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalOwnedBuffer

    init(
        generic_base: SignalType_MutPointer_SignalOwnedBuffer?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalOwnedBuffer? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedPairOfCStringPtrCStringPtr: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalPairOfCStringPtrCStringPtr

    init(
        generic_base: SignalType_MutPointer_SignalPairOfCStringPtrCStringPtr?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalPairOfCStringPtrCStringPtr? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedPairOfCStringPtrAuthCheckResultFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalPairOfCStringPtrAuthCheckResultFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalPairOfCStringPtrAuthCheckResultFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalPairOfCStringPtrAuthCheckResultFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedPairOfCStringPtrBadgeFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalPairOfCStringPtrBadgeFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalPairOfCStringPtrBadgeFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalPairOfCStringPtrBadgeFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedBridgeConfirmedMfaKeyFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalBridgeConfirmedMfaKeyFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalBridgeConfirmedMfaKeyFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalBridgeConfirmedMfaKeyFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaOutcomeFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalBridgeCopyBackupMediaOutcomeFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalBridgeCopyBackupMediaOutcomeFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalBridgeCopyBackupMediaOutcomeFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedBridgeDeleteBackupMediaItemFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalBridgeDeleteBackupMediaItemFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalBridgeDeleteBackupMediaItemFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalBridgeDeleteBackupMediaItemFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedBadgeEntitlementFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalBadgeEntitlementFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalBadgeEntitlementFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalBadgeEntitlementFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedBadgeSvgFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalBadgeSvgFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalBadgeSvgFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalBadgeSvgFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedCurrencyInternalFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalCurrencyInternalFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalCurrencyInternalFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalCurrencyInternalFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedDeviceCapabilityInternalFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalDeviceCapabilityInternalFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalDeviceCapabilityInternalFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalDeviceCapabilityInternalFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalLinkedDeviceInternalFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalLinkedDeviceInternalFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalLinkedDeviceInternalFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedListMediaItemFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalListMediaItemFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalListMediaItemFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalListMediaItemFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalOwnedBufferOfMaxAlignedS3UploadFormInternalFfiResult: SignalOwnedBufferOfMaxAligned {

    typealias Element = SignalS3UploadFormInternalFfiResult

    init(
        generic_base: SignalType_MutPointer_SignalS3UploadFormInternalFfiResult?,
        generic_length: size_t,
        generic_size_bytes: size_t,
    ) {
        self.init(
            base: generic_base,
            length: generic_length,
            size_bytes: generic_size_bytes,

        )
    }

    var generic_base: SignalType_MutPointer_SignalS3UploadFormInternalFfiResult? {
        get { self.base }
        set { base = newValue }
    }

    var generic_length: size_t {
        get { self.length }
        set { length = newValue }
    }

    var generic_size_bytes: size_t {
        get { self.size_bytes }
        set { size_bytes = newValue }
    }

}

extension SignalPairOfCStringPtrCStringPtr: SignalPairOf {

    typealias First = SignalCStringPtr?

    typealias Second = SignalCStringPtr?

    init(
        generic_first: SignalCStringPtr?,
        generic_second: SignalCStringPtr?,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalCStringPtr? {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalCStringPtr? {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfCStringPtrc_uchar32: SignalPairOf {

    typealias First = SignalCStringPtr?

    typealias Second = SignalType_FixedArray32_uint8_t

    init(
        generic_first: SignalCStringPtr?,
        generic_second: SignalType_FixedArray32_uint8_t,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalCStringPtr? {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalType_FixedArray32_uint8_t {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfCStringPtrbool: SignalPairOf {

    typealias First = SignalCStringPtr?

    typealias Second = CBool

    init(
        generic_first: SignalCStringPtr?,
        generic_second: CBool,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalCStringPtr? {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: CBool {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfCStringPtrOwnedBuffer: SignalPairOf {

    typealias First = SignalCStringPtr?

    typealias Second = SignalOwnedBuffer

    init(
        generic_first: SignalCStringPtr?,
        generic_second: SignalOwnedBuffer,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalCStringPtr? {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalOwnedBuffer {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfCStringPtrAuthCheckResultFfiResult: SignalPairOf {

    typealias First = SignalCStringPtr?

    typealias Second = SignalAuthCheckResultFfiResult

    init(
        generic_first: SignalCStringPtr?,
        generic_second: SignalAuthCheckResultFfiResult,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalCStringPtr? {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalAuthCheckResultFfiResult {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfCStringPtrBadgeFfiResult: SignalPairOf {

    typealias First = SignalCStringPtr?

    typealias Second = SignalBadgeFfiResult

    init(
        generic_first: SignalCStringPtr?,
        generic_second: SignalBadgeFfiResult,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalCStringPtr? {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalBadgeFfiResult {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfCStringPtru32: SignalPairOf {

    typealias First = SignalCStringPtr?

    typealias Second = UInt32

    init(
        generic_first: SignalCStringPtr?,
        generic_second: UInt32,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalCStringPtr? {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: UInt32 {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfMutPointerPrivateKeyMutPointerPublicKey: SignalPairOf {

    typealias First = SignalMutPointerPrivateKey

    typealias Second = SignalMutPointerPublicKey

    init(
        generic_first: SignalMutPointerPrivateKey,
        generic_second: SignalMutPointerPublicKey,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalMutPointerPrivateKey {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalMutPointerPublicKey {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfMutPointerPublicKeyMutPointerPrivateKey: SignalPairOf {

    typealias First = SignalMutPointerPublicKey

    typealias Second = SignalMutPointerPrivateKey

    init(
        generic_first: SignalMutPointerPublicKey,
        generic_second: SignalMutPointerPrivateKey,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalMutPointerPublicKey {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalMutPointerPrivateKey {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr: SignalPairOf {

    typealias First = SignalOwnedBufferOfCStringPtr

    typealias Second = SignalOwnedBufferOfCStringPtr

    init(
        generic_first: SignalOwnedBufferOfCStringPtr,
        generic_second: SignalOwnedBufferOfCStringPtr,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalOwnedBufferOfCStringPtr {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalOwnedBufferOfCStringPtr {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfOwnedBufferi64: SignalPairOf {

    typealias First = SignalOwnedBuffer

    typealias Second = Int64

    init(
        generic_first: SignalOwnedBuffer,
        generic_second: Int64,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalOwnedBuffer {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: Int64 {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfOwnedBufferOwnedBuffer: SignalPairOf {

    typealias First = SignalOwnedBuffer

    typealias Second = SignalOwnedBuffer

    init(
        generic_first: SignalOwnedBuffer,
        generic_second: SignalOwnedBuffer,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalOwnedBuffer {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: SignalOwnedBuffer {
        get { self.second }
        set { second = newValue }
    }

}

extension SignalPairOfPairOfCStringPtrOwnedBufferi64: SignalPairOf {

    typealias First = SignalPairOfCStringPtrOwnedBuffer

    typealias Second = Int64

    init(
        generic_first: SignalPairOfCStringPtrOwnedBuffer,
        generic_second: Int64,
    ) {
        self.init(
            first: generic_first,
            second: generic_second,

        )
    }

    var generic_first: SignalPairOfCStringPtrOwnedBuffer {
        get { self.first }
        set { first = newValue }
    }

    var generic_second: Int64 {
        get { self.second }
        set { second = newValue }
    }

}

internal enum FixedByteArrayHelper10: FixedByteArrayHelper {
    typealias Ffi = (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8)
    static func count() -> Int {
        10
    }
    static func emptyFfi() -> Ffi {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

internal enum FixedByteArrayHelper15: FixedByteArrayHelper {
    typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    static func count() -> Int {
        15
    }
    static func emptyFfi() -> Ffi {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

internal enum FixedByteArrayHelper16: FixedByteArrayHelper {
    typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    static func count() -> Int {
        16
    }
    static func emptyFfi() -> Ffi {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

internal enum FixedByteArrayHelper32: FixedByteArrayHelper {
    typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    static func count() -> Int {
        32
    }
    static func emptyFfi() -> Ffi {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
}

internal enum FixedByteArrayHelper64: FixedByteArrayHelper {
    typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    static func count() -> Int {
        64
    }
    static func emptyFfi() -> Ffi {
        (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    }
}

internal enum FixedByteArrayHelper153: FixedByteArrayHelper {
    typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    static func count() -> Int {
        153
    }
    static func emptyFfi() -> Ffi {
        (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    }
}

internal enum FixedByteArrayHelper329: FixedByteArrayHelper {
    typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    static func count() -> Int {
        329
    }
    static func emptyFfi() -> Ffi {
        (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0
        )
    }
}

internal enum FixedByteArrayHelper473: FixedByteArrayHelper {
    typealias Ffi = (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    static func count() -> Int {
        473
    }
    static func emptyFfi() -> Ffi {
        (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0
        )
    }
}

/*
// AccountEntitlements

internal struct AccountEntitlements {
    var badges: [BadgeEntitlement]
    var backup: BackupEntitlement?

}

*/

/*
// AuthCheckResult

internal enum AuthCheckResult {
    case match
    case noMatch
    case invalid
}

*/

/*
// BackupEntitlement

internal struct BackupEntitlement {
    var level: Int64
    var expiration: Date

}

*/

/*
// Badge

internal struct Badge {
    var id: String
    var category: String
    var name: String
    var description: String
    var sprites6: [String]
    var svg: String
    var svgs: [BadgeSvg]

}

*/

/*
// BadgeEntitlement

internal struct BadgeEntitlement {
    var badgeId: String
    var expiration: Date
    var visible: Bool

}

*/

/*
// BadgeSvg

internal struct BadgeSvg {
    var light: String
    var dark: String

}

*/

/*
// BadgeVisibility

internal enum BadgeVisibility {
    case doNotSet
    case setVisible
    case setPrimary
}

*/

internal struct BridgeAccountIdentity {
    var aci: Aci
    var pni: Pni?
    var e164: String?
    var usernameHash: Data?
    var usernameLinkHandle: UUID?

}

/*
// ChallengeAnswer

internal enum BridgeChallengeAnswer {
    case push(String)
    case captcha(String)
}

*/

internal struct BridgeConfirmedMfaKey {
    var id: Int32
    var metadata: BridgeConfirmedMfaKeyMetadata
    var kind: BridgeMfaKeyKind

}

internal enum BridgeConfirmedMfaKeyMetadata {
    case metadata(BridgeMfaMetadata)
    case unreadable
}

internal struct BridgeCopyBackupMediaItem {
    var sourceAttachmentCdn: Int32
    var sourceKey: String
    var objectLength: Int64
    var mediaId: Data
    var encryptionKey: Data

}

internal struct BridgeCopyBackupMediaOutcome {
    var mediaId: Data
    var result: BridgeCopyBackupMediaResult

}

internal enum BridgeCopyBackupMediaResult {
    case success(cdn: Int32)
    case sourceNotFound
    case wrongSourceLength
    case outOfSpace
}

internal struct BridgeDeleteBackupMediaItem {
    var mediaId: Data
    var cdn: Int32

}

internal struct BridgeMediaBackupInfo {
    var backupDir: String
    var mediaDir: String
    var usedSpace: Int64

}

internal struct BridgeMessageBackupInfo {
    var backupDir: String
    var cdn: Int32
    var backupName: String

}

internal enum BridgeMfaKeyKind {
    case totp
    case webAuthn
    case unknown
}

internal struct BridgeMfaMetadata {
    var name: String
    var createdAt: Date

}

internal enum BridgeMfaVerificationCredential {
    case totp(password: Int32)
    case webAuthn(json: String)
}

internal struct BridgePendingTotpKey {
    var key: Data
    var parameters: BridgeTotpParameters

}

internal struct BridgePreKeyCounts {
    var aciEcPreKeyCount: Int32
    var aciKemPreKeyCount: Int32
    var pniEcPreKeyCount: Int32
    var pniKemPreKeyCount: Int32

}

internal struct BridgeTotpParameters {
    var algorithm: String
    var passwordLength: Int32
    var timeStepSeconds: Int32

}

/*
// WebAuthnAuthenticationParameters

internal struct BridgeWebAuthnAuthenticationParameters {
    var challenge: Data
    var timeoutSeconds: Int32
    var allowedCredentialIds: [Data]

}

*/

internal struct BridgeWebAuthnCreateParameters {
    var userHandle: Data
    var allowedAlgorithms: [Int32]
    var excludeCredentialIds: [Data]

}

/*
// CallQualitySurvey

internal struct CallQualitySurveyInternal {
    var userSatisfied: Bool
    var callQualityIssues: [String]
    var additionalIssuesDescription: String?
    var debugLogUrl: String?
    var startTimestamp: Date
    var endTimestamp: Date
    var callType: String
    var success: Bool
    var callEndReason: String
    var connectionRttMedian: Float?
    var audioRttMedian: Float?
    var videoRttMedian: Float?
    var audioRecvJitterMedian: Float?
    var videoRecvJitterMedian: Float?
    var audioSendJitterMedian: Float?
    var videoSendJitterMedian: Float?
    var audioRecvPacketLossFraction: Float?
    var videoRecvPacketLossFraction: Float?
    var audioSendPacketLossFraction: Float?
    var videoSendPacketLossFraction: Float?
    var callTelemetry: Data?
    var callIdHash: Data?

}

*/

/*
// ChargeFailure

internal struct ChargeFailure {
    var processor: PaymentProvider
    var code: String
    var message: String
    var outcomeNetworkStatus: String?
    var outcomeReason: String?
    var outcomeType: String?

}

*/

internal struct CopyBackupMediaNextChunk {
    var chunk: [BridgeCopyBackupMediaOutcome]
    var termination: BulkPolledStreamTermination?

}

internal struct CurrencyConversionsInternal {
    var timestampMs: Date
    var currencies: [CurrencyInternal]

}

internal struct CurrencyInternal {
    var base: String
    var conversions: [(String, String)]

}

internal struct DeleteBackupMediaNextChunk {
    var chunk: [BridgeDeleteBackupMediaItem]
    var termination: BulkPolledStreamTermination?

}

/*
// DeviceCapability

internal enum DeviceCapabilityInternal {
    case storage
    case transfer
    case attachmentBackfill
    case sparsePostQuantumRatchet
    case profilesV2
    case usernameChangeSyncMessage
    case optionalPhoneNumber
}

*/

/*
// FetchedProfile

internal struct FetchedProfile {
    var profile: Profile
    var etag: Data?
    var v2DataHash: Data?
    var identityKey: IdentityKey
    var unidentifiedAccessKeyFingerprint: Data?
    var unrestrictedUnidentifiedAccess: Bool

}

*/

/*
// GetStickerUploadFormsResponse

internal struct GetStickerUploadFormsResponse {
    var packId: String
    var manifestUploadForm: S3UploadForm
    var stickerUploadForms: [S3UploadForm]

}

*/

/*
// LinkedDevice

internal struct LinkedDeviceInternal {
    var id: DeviceId
    var encryptedName: Data
    var lastSeen: Date
    var registrationId: UInt16
    var createdAtCiphertext: Data

}

*/

internal struct ListMediaItem {
    var cdn: Int32
    var mediaId: Data
    var objectLength: Int64

}

internal struct ListMediaResponse {
    var items: [ListMediaItem]
    var backupDir: String
    var mediaDir: String
    var cursor: String?

}

/*
// LoginReceiptLevel

internal enum LoginReceiptLevel {
    case normal
    case sandbox
}

*/

/*
// PaymentProvider

internal enum PaymentProviderInternal {
    case googlePlayBilling
    case appleAppStore
    case stripe
    case braintree
}

*/

/*
// Profile

internal struct Profile {
    var givenName: String
    var familyName: String
    var about: String
    var aboutEmoji: String
    var avatar: CdnUrl?
    var phoneNumberSharing: Bool?
    var paymentAddress: Data?
    var badgeIds: [String]

}

*/

/*
// ProfileFieldWithMaxLength

internal enum ProfileFieldWithMaxLength {
    case givenName
    case familyName
    case about
    case aboutEmoji
    case avatar
    case paymentAddress
}

*/

internal enum ProfileValidationErrorInternal {
    case fieldTooLong(field: ProfileFieldWithMaxLength, len: Int32, maxLen: Int32)
    case givenNameEmpty
}

/*
// S3UploadForm

internal struct S3UploadFormInternal {
    var key: String
    var credential: String
    var acl: String
    var algorithm: String
    var date: String
    var policy: String
    var signature: String

}

*/

/*
// StartMfaVerificationResponse

internal struct StartMfaVerificationResponse {
    var hasTotp: Bool
    var webauthnParams: WebAuthnAuthenticationParameters?

}

*/

/*
// TaggedBadges

internal struct TaggedBadges {
    var badges: [String: Badge]
    var etag: Data

}

*/

/*
// UnauthProfileAuthorization

internal enum UnauthProfileAuthorization {
    case accessKey(Data)
    case groupSend(GroupSendFullToken)
}

*/

internal enum DerivedReturnConverterAccountEntitlements: NiceReturnConverter {
    typealias NiceReturn = AccountEntitlements
    typealias FfiReturn = SignalAccountEntitlementsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalAccountEntitlementsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let badges = Result {
            try ArrayReturnConverter<
                DerivedReturnConverterBadgeEntitlement, SignalOwnedBufferOfMaxAlignedBadgeEntitlementFfiResult
            >.convertReturn(consuming: ffiValue.badges)
        }
        let backup = Result {
            try OptionalReturnConverter<
                DerivedReturnConverterBackupEntitlement, SignalOptionalOfBackupEntitlementFfiResult
            >.convertReturn(consuming: ffiValue.backup)
        }

        return AccountEntitlements(badges: try badges.get(), backup: try backup.get())
    }
}

internal enum DerivedReturnConverterAuthCheckResult: NiceReturnConverter {
    typealias NiceReturn = AuthCheckResult
    typealias FfiReturn = SignalAuthCheckResultFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalAuthCheckResultFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalAuthCheckResultFfiResultMatch:
            return AuthCheckResult.match
        case SignalAuthCheckResultFfiResultNoMatch:
            return AuthCheckResult.noMatch
        case SignalAuthCheckResultFfiResultInvalid:
            return AuthCheckResult.invalid
        default:
            throw SignalError.internalError("Unexpected enum tag for AuthCheckResult: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterBackupEntitlement: NiceReturnConverter {
    typealias NiceReturn = BackupEntitlement
    typealias FfiReturn = SignalBackupEntitlementFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBackupEntitlementFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let level = Result { try IdentityResultConverter<Int64>.convertReturn(consuming: ffiValue.level) }
        let expiration = Result { try TimestampConverter.convertReturn(consuming: ffiValue.expiration) }

        return BackupEntitlement(level: try level.get(), expiration: try expiration.get())
    }
}

internal enum DerivedReturnConverterBadge: NiceReturnConverter {
    typealias NiceReturn = Badge
    typealias FfiReturn = SignalBadgeFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBadgeFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let id = Result { try StringConverter.convertReturn(consuming: ffiValue.id) }
        let category = Result { try StringConverter.convertReturn(consuming: ffiValue.category) }
        let name = Result { try StringConverter.convertReturn(consuming: ffiValue.name) }
        let description = Result { try StringConverter.convertReturn(consuming: ffiValue.description) }
        let sprites6 = Result {
            try ArrayReturnConverter<StringConverter, SignalOwnedBufferOfMaxAlignedCStringPtr>.convertReturn(
                consuming: ffiValue.sprites6
            )
        }
        let svg = Result { try StringConverter.convertReturn(consuming: ffiValue.svg) }
        let svgs = Result {
            try ArrayReturnConverter<DerivedReturnConverterBadgeSvg, SignalOwnedBufferOfMaxAlignedBadgeSvgFfiResult>
                .convertReturn(consuming: ffiValue.svgs)
        }

        return Badge(
            id: try id.get(),
            category: try category.get(),
            name: try name.get(),
            description: try description.get(),
            sprites6: try sprites6.get(),
            svg: try svg.get(),
            svgs: try svgs.get()
        )
    }
}

internal enum DerivedReturnConverterBadgeEntitlement: NiceReturnConverter {
    typealias NiceReturn = BadgeEntitlement
    typealias FfiReturn = SignalBadgeEntitlementFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBadgeEntitlementFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let badge_id = Result { try StringConverter.convertReturn(consuming: ffiValue.badge_id) }
        let expiration = Result { try TimestampConverter.convertReturn(consuming: ffiValue.expiration) }
        let visible = Result { try IdentityResultConverter<Bool>.convertReturn(consuming: ffiValue.visible) }

        return BadgeEntitlement(
            badgeId: try badge_id.get(),
            expiration: try expiration.get(),
            visible: try visible.get()
        )
    }
}

internal enum DerivedReturnConverterBadgeSvg: NiceReturnConverter {
    typealias NiceReturn = BadgeSvg
    typealias FfiReturn = SignalBadgeSvgFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBadgeSvgFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let light = Result { try StringConverter.convertReturn(consuming: ffiValue.light) }
        let dark = Result { try StringConverter.convertReturn(consuming: ffiValue.dark) }

        return BadgeSvg(light: try light.get(), dark: try dark.get())
    }
}

internal enum DerivedReturnConverterBridgeAccountIdentity: NiceReturnConverter {
    typealias NiceReturn = BridgeAccountIdentity
    typealias FfiReturn = SignalBridgeAccountIdentityFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeAccountIdentityFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let aci = Result { try AciConverter.convertReturn(consuming: ffiValue.aci) }
        let pni = Result {
            try OptionalReturnConverter<PniConverter, SignalOptionalOfc_uchar17>.convertReturn(consuming: ffiValue.pni)
        }
        let e164 = Result { try OptionalStringConverter.convertReturn(consuming: ffiValue.e164) }
        let username_hash = Result {
            try OptionalReturnConverter<DataConverter, SignalOptionalOfOwnedBuffer>.convertReturn(
                consuming: ffiValue.username_hash
            )
        }
        let username_link_handle = Result {
            try OptionalReturnConverter<UuidNiceConverter, SignalOptionalOfUuid>.convertReturn(
                consuming: ffiValue.username_link_handle
            )
        }

        return BridgeAccountIdentity(
            aci: try aci.get(),
            pni: try pni.get(),
            e164: try e164.get(),
            usernameHash: try username_hash.get(),
            usernameLinkHandle: try username_link_handle.get()
        )
    }
}

internal enum DerivedReturnConverterBridgeConfirmedMfaKey: NiceReturnConverter {
    typealias NiceReturn = BridgeConfirmedMfaKey
    typealias FfiReturn = SignalBridgeConfirmedMfaKeyFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeConfirmedMfaKeyFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let id = Result { try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.id) }
        let metadata = Result {
            try DerivedReturnConverterBridgeConfirmedMfaKeyMetadata.convertReturn(consuming: ffiValue.metadata)
        }
        let kind = Result { try DerivedReturnConverterBridgeMfaKeyKind.convertReturn(consuming: ffiValue.kind) }

        return BridgeConfirmedMfaKey(id: try id.get(), metadata: try metadata.get(), kind: try kind.get())
    }
}

internal enum DerivedReturnConverterBridgeConfirmedMfaKeyMetadata: NiceReturnConverter {
    typealias NiceReturn = BridgeConfirmedMfaKeyMetadata
    typealias FfiReturn = SignalBridgeConfirmedMfaKeyMetadataFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeConfirmedMfaKeyMetadataFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalBridgeConfirmedMfaKeyMetadataFfiResultMetadata:
            let _0 = Result {
                try DerivedReturnConverterBridgeMfaMetadata.convertReturn(
                    consuming: ffiValue.metadata._0
                )
            }
            return BridgeConfirmedMfaKeyMetadata.metadata(try _0.get())
        case SignalBridgeConfirmedMfaKeyMetadataFfiResultUnreadable:
            return BridgeConfirmedMfaKeyMetadata.unreadable
        default:
            throw SignalError.internalError("Unexpected enum tag for BridgeConfirmedMfaKeyMetadata: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterBridgeCopyBackupMediaOutcome: NiceReturnConverter {
    typealias NiceReturn = BridgeCopyBackupMediaOutcome
    typealias FfiReturn = SignalBridgeCopyBackupMediaOutcomeFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeCopyBackupMediaOutcomeFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let media_id = Result {
            try FixedByteArrayConverter<FixedByteArrayHelper15>.convertReturn(consuming: ffiValue.media_id)
        }
        let result = Result {
            try DerivedReturnConverterBridgeCopyBackupMediaResult.convertReturn(consuming: ffiValue.result)
        }

        return BridgeCopyBackupMediaOutcome(mediaId: try media_id.get(), result: try result.get())
    }
}

internal enum DerivedReturnConverterBridgeCopyBackupMediaResult: NiceReturnConverter {
    typealias NiceReturn = BridgeCopyBackupMediaResult
    typealias FfiReturn = SignalBridgeCopyBackupMediaResultFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeCopyBackupMediaResultFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalBridgeCopyBackupMediaResultFfiResultSuccess:
            let cdn = Result {
                try IdentityResultConverter<Int32>.convertReturn(
                    consuming: ffiValue.success.cdn
                )
            }
            return BridgeCopyBackupMediaResult.success(cdn: try cdn.get())
        case SignalBridgeCopyBackupMediaResultFfiResultSourceNotFound:
            return BridgeCopyBackupMediaResult.sourceNotFound
        case SignalBridgeCopyBackupMediaResultFfiResultWrongSourceLength:
            return BridgeCopyBackupMediaResult.wrongSourceLength
        case SignalBridgeCopyBackupMediaResultFfiResultOutOfSpace:
            return BridgeCopyBackupMediaResult.outOfSpace
        default:
            throw SignalError.internalError("Unexpected enum tag for BridgeCopyBackupMediaResult: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterBridgeDeleteBackupMediaItem: NiceReturnConverter {
    typealias NiceReturn = BridgeDeleteBackupMediaItem
    typealias FfiReturn = SignalBridgeDeleteBackupMediaItemFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeDeleteBackupMediaItemFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let media_id = Result {
            try FixedByteArrayConverter<FixedByteArrayHelper15>.convertReturn(consuming: ffiValue.media_id)
        }
        let cdn = Result { try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.cdn) }

        return BridgeDeleteBackupMediaItem(mediaId: try media_id.get(), cdn: try cdn.get())
    }
}

internal enum DerivedReturnConverterBridgeMediaBackupInfo: NiceReturnConverter {
    typealias NiceReturn = BridgeMediaBackupInfo
    typealias FfiReturn = SignalBridgeMediaBackupInfoFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeMediaBackupInfoFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let backup_dir = Result { try StringConverter.convertReturn(consuming: ffiValue.backup_dir) }
        let media_dir = Result { try StringConverter.convertReturn(consuming: ffiValue.media_dir) }
        let used_space = Result { try IdentityResultConverter<Int64>.convertReturn(consuming: ffiValue.used_space) }

        return BridgeMediaBackupInfo(
            backupDir: try backup_dir.get(),
            mediaDir: try media_dir.get(),
            usedSpace: try used_space.get()
        )
    }
}

internal enum DerivedReturnConverterBridgeMessageBackupInfo: NiceReturnConverter {
    typealias NiceReturn = BridgeMessageBackupInfo
    typealias FfiReturn = SignalBridgeMessageBackupInfoFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeMessageBackupInfoFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let backup_dir = Result { try StringConverter.convertReturn(consuming: ffiValue.backup_dir) }
        let cdn = Result { try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.cdn) }
        let backup_name = Result { try StringConverter.convertReturn(consuming: ffiValue.backup_name) }

        return BridgeMessageBackupInfo(
            backupDir: try backup_dir.get(),
            cdn: try cdn.get(),
            backupName: try backup_name.get()
        )
    }
}

internal enum DerivedReturnConverterBridgeMfaKeyKind: NiceReturnConverter {
    typealias NiceReturn = BridgeMfaKeyKind
    typealias FfiReturn = SignalBridgeMfaKeyKindFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeMfaKeyKindFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalBridgeMfaKeyKindFfiResultTotp:
            return BridgeMfaKeyKind.totp
        case SignalBridgeMfaKeyKindFfiResultWebAuthn:
            return BridgeMfaKeyKind.webAuthn
        case SignalBridgeMfaKeyKindFfiResultUnknown:
            return BridgeMfaKeyKind.unknown
        default:
            throw SignalError.internalError("Unexpected enum tag for BridgeMfaKeyKind: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterBridgeMfaMetadata: NiceReturnConverter {
    typealias NiceReturn = BridgeMfaMetadata
    typealias FfiReturn = SignalBridgeMfaMetadataFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeMfaMetadataFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let name = Result { try StringConverter.convertReturn(consuming: ffiValue.name) }
        let created_at = Result { try TimestampConverter.convertReturn(consuming: ffiValue.created_at) }

        return BridgeMfaMetadata(name: try name.get(), createdAt: try created_at.get())
    }
}

internal enum DerivedReturnConverterBridgePendingTotpKey: NiceReturnConverter {
    typealias NiceReturn = BridgePendingTotpKey
    typealias FfiReturn = SignalBridgePendingTotpKeyFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgePendingTotpKeyFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let key = Result { try DataConverter.convertReturn(consuming: ffiValue.key) }
        let parameters = Result {
            try DerivedReturnConverterBridgeTotpParameters.convertReturn(consuming: ffiValue.parameters)
        }

        return BridgePendingTotpKey(key: try key.get(), parameters: try parameters.get())
    }
}

internal enum DerivedReturnConverterBridgePreKeyCounts: NiceReturnConverter {
    typealias NiceReturn = BridgePreKeyCounts
    typealias FfiReturn = SignalBridgePreKeyCountsFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgePreKeyCountsFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let aci_ec_pre_key_count = Result {
            try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.aci_ec_pre_key_count)
        }
        let aci_kem_pre_key_count = Result {
            try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.aci_kem_pre_key_count)
        }
        let pni_ec_pre_key_count = Result {
            try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.pni_ec_pre_key_count)
        }
        let pni_kem_pre_key_count = Result {
            try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.pni_kem_pre_key_count)
        }

        return BridgePreKeyCounts(
            aciEcPreKeyCount: try aci_ec_pre_key_count.get(),
            aciKemPreKeyCount: try aci_kem_pre_key_count.get(),
            pniEcPreKeyCount: try pni_ec_pre_key_count.get(),
            pniKemPreKeyCount: try pni_kem_pre_key_count.get()
        )
    }
}

internal enum DerivedReturnConverterBridgeTotpParameters: NiceReturnConverter {
    typealias NiceReturn = BridgeTotpParameters
    typealias FfiReturn = SignalBridgeTotpParametersFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeTotpParametersFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let algorithm = Result { try StringConverter.convertReturn(consuming: ffiValue.algorithm) }
        let password_length = Result {
            try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.password_length)
        }
        let time_step_seconds = Result {
            try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.time_step_seconds)
        }

        return BridgeTotpParameters(
            algorithm: try algorithm.get(),
            passwordLength: try password_length.get(),
            timeStepSeconds: try time_step_seconds.get()
        )
    }
}

internal enum DerivedReturnConverterBridgeWebAuthnAuthenticationParameters: NiceReturnConverter {
    typealias NiceReturn = WebAuthnAuthenticationParameters
    typealias FfiReturn = SignalBridgeWebAuthnAuthenticationParametersFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeWebAuthnAuthenticationParametersFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let challenge = Result { try DataConverter.convertReturn(consuming: ffiValue.challenge) }
        let timeout_seconds = Result {
            try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.timeout_seconds)
        }
        let allowed_credential_ids = Result {
            try ArrayReturnConverter<DataConverter, SignalOwnedBufferOfMaxAlignedOwnedBuffer>.convertReturn(
                consuming: ffiValue.allowed_credential_ids
            )
        }

        return WebAuthnAuthenticationParameters(
            challenge: try challenge.get(),
            timeoutSeconds: try timeout_seconds.get(),
            allowedCredentialIds: try allowed_credential_ids.get()
        )
    }
}

internal enum DerivedReturnConverterBridgeWebAuthnCreateParameters: NiceReturnConverter {
    typealias NiceReturn = BridgeWebAuthnCreateParameters
    typealias FfiReturn = SignalBridgeWebAuthnCreateParametersFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalBridgeWebAuthnCreateParametersFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let user_handle = Result { try DataConverter.convertReturn(consuming: ffiValue.user_handle) }
        let allowed_algorithms = Result {
            try ArrayReturnConverter<IdentityResultConverter<Int32>, SignalOwnedBufferOfMaxAlignedi32>.convertReturn(
                consuming: ffiValue.allowed_algorithms
            )
        }
        let exclude_credential_ids = Result {
            try ArrayReturnConverter<DataConverter, SignalOwnedBufferOfMaxAlignedOwnedBuffer>.convertReturn(
                consuming: ffiValue.exclude_credential_ids
            )
        }

        return BridgeWebAuthnCreateParameters(
            userHandle: try user_handle.get(),
            allowedAlgorithms: try allowed_algorithms.get(),
            excludeCredentialIds: try exclude_credential_ids.get()
        )
    }
}

internal enum DerivedReturnConverterChargeFailure: NiceReturnConverter {
    typealias NiceReturn = ChargeFailure
    typealias FfiReturn = SignalChargeFailureFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalChargeFailureFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let processor = Result {
            try DerivedReturnConverterPaymentProviderInternal.convertReturn(consuming: ffiValue.processor)
        }
        let code = Result { try StringConverter.convertReturn(consuming: ffiValue.code) }
        let message = Result { try StringConverter.convertReturn(consuming: ffiValue.message) }
        let outcome_network_status = Result {
            try OptionalStringConverter.convertReturn(consuming: ffiValue.outcome_network_status)
        }
        let outcome_reason = Result { try OptionalStringConverter.convertReturn(consuming: ffiValue.outcome_reason) }
        let outcome_type = Result { try OptionalStringConverter.convertReturn(consuming: ffiValue.outcome_type) }

        return ChargeFailure(
            processor: try processor.get(),
            code: try code.get(),
            message: try message.get(),
            outcomeNetworkStatus: try outcome_network_status.get(),
            outcomeReason: try outcome_reason.get(),
            outcomeType: try outcome_type.get()
        )
    }
}

internal enum DerivedReturnConverterCopyBackupMediaNextChunk: NiceReturnConverter {
    typealias NiceReturn = CopyBackupMediaNextChunk
    typealias FfiReturn = SignalCopyBackupMediaNextChunkFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalCopyBackupMediaNextChunkFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let chunk = Result {
            try ArrayReturnConverter<
                DerivedReturnConverterBridgeCopyBackupMediaOutcome,
                SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaOutcomeFfiResult
            >.convertReturn(consuming: ffiValue.chunk)
        }
        let termination = Result {
            try BulkPolledStreamTerminationConverter.convertReturn(consuming: ffiValue.termination)
        }

        return CopyBackupMediaNextChunk(chunk: try chunk.get(), termination: try termination.get())
    }
}

internal enum DerivedReturnConverterCurrencyConversionsInternal: NiceReturnConverter {
    typealias NiceReturn = CurrencyConversionsInternal
    typealias FfiReturn = SignalCurrencyConversionsInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalCurrencyConversionsInternalFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let timestamp_ms = Result { try TimestampConverter.convertReturn(consuming: ffiValue.timestamp_ms) }
        let currencies = Result {
            try ArrayReturnConverter<
                DerivedReturnConverterCurrencyInternal, SignalOwnedBufferOfMaxAlignedCurrencyInternalFfiResult
            >.convertReturn(consuming: ffiValue.currencies)
        }

        return CurrencyConversionsInternal(timestampMs: try timestamp_ms.get(), currencies: try currencies.get())
    }
}

internal enum DerivedReturnConverterCurrencyInternal: NiceReturnConverter {
    typealias NiceReturn = CurrencyInternal
    typealias FfiReturn = SignalCurrencyInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalCurrencyInternalFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let base = Result { try StringConverter.convertReturn(consuming: ffiValue.base) }
        let conversions = Result {
            try ArrayReturnConverter<
                PairOfResultConverter<StringConverter, StringConverter, SignalPairOfCStringPtrCStringPtr>,
                SignalOwnedBufferOfMaxAlignedPairOfCStringPtrCStringPtr
            >.convertReturn(consuming: ffiValue.conversions)
        }

        return CurrencyInternal(base: try base.get(), conversions: try conversions.get())
    }
}

internal enum DerivedReturnConverterDeleteBackupMediaNextChunk: NiceReturnConverter {
    typealias NiceReturn = DeleteBackupMediaNextChunk
    typealias FfiReturn = SignalDeleteBackupMediaNextChunkFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalDeleteBackupMediaNextChunkFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let chunk = Result {
            try ArrayReturnConverter<
                DerivedReturnConverterBridgeDeleteBackupMediaItem,
                SignalOwnedBufferOfMaxAlignedBridgeDeleteBackupMediaItemFfiResult
            >.convertReturn(consuming: ffiValue.chunk)
        }
        let termination = Result {
            try BulkPolledStreamTerminationConverter.convertReturn(consuming: ffiValue.termination)
        }

        return DeleteBackupMediaNextChunk(chunk: try chunk.get(), termination: try termination.get())
    }
}

internal enum DerivedReturnConverterDeviceCapabilityInternal: NiceReturnConverter {
    typealias NiceReturn = DeviceCapability
    typealias FfiReturn = SignalDeviceCapabilityInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalDeviceCapabilityInternalFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalDeviceCapabilityInternalFfiResultStorage:
            return DeviceCapability.storage
        case SignalDeviceCapabilityInternalFfiResultTransfer:
            return DeviceCapability.transfer
        case SignalDeviceCapabilityInternalFfiResultAttachmentBackfill:
            return DeviceCapability.attachmentBackfill
        case SignalDeviceCapabilityInternalFfiResultSparsePostQuantumRatchet:
            return DeviceCapability.sparsePostQuantumRatchet
        case SignalDeviceCapabilityInternalFfiResultProfilesV2:
            return DeviceCapability.profilesV2
        case SignalDeviceCapabilityInternalFfiResultUsernameChangeSyncMessage:
            return DeviceCapability.usernameChangeSyncMessage
        case SignalDeviceCapabilityInternalFfiResultOptionalPhoneNumber:
            return DeviceCapability.optionalPhoneNumber
        default:
            throw SignalError.internalError("Unexpected enum tag for DeviceCapabilityInternal: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterFetchedProfile: NiceReturnConverter {
    typealias NiceReturn = FetchedProfile
    typealias FfiReturn = SignalFetchedProfileFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalFetchedProfileFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let profile = Result { try DerivedReturnConverterProfile.convertReturn(consuming: ffiValue.profile) }
        let etag = Result {
            try OptionalReturnConverter<FixedByteArrayConverter<FixedByteArrayHelper10>, SignalOptionalOfc_uchar10>
                .convertReturn(consuming: ffiValue.etag)
        }
        let v2_data_hash = Result {
            try OptionalReturnConverter<FixedByteArrayConverter<FixedByteArrayHelper32>, SignalOptionalOfc_uchar32>
                .convertReturn(consuming: ffiValue.v2_data_hash)
        }
        let identity_key = Result {
            try IdentityKeyResultConverter<BridgeHandleConverter<SignalMutPointerPublicKey, PublicKey>>.convertReturn(
                consuming: ffiValue.identity_key
            )
        }
        let unidentified_access_key_fingerprint = Result {
            try OptionalReturnConverter<FixedByteArrayConverter<FixedByteArrayHelper32>, SignalOptionalOfc_uchar32>
                .convertReturn(consuming: ffiValue.unidentified_access_key_fingerprint)
        }
        let unrestricted_unidentified_access = Result {
            try IdentityResultConverter<Bool>.convertReturn(consuming: ffiValue.unrestricted_unidentified_access)
        }

        return FetchedProfile(
            profile: try profile.get(),
            etag: try etag.get(),
            v2DataHash: try v2_data_hash.get(),
            identityKey: try identity_key.get(),
            unidentifiedAccessKeyFingerprint: try unidentified_access_key_fingerprint.get(),
            unrestrictedUnidentifiedAccess: try unrestricted_unidentified_access.get()
        )
    }
}

internal enum DerivedReturnConverterGetStickerUploadFormsResponse: NiceReturnConverter {
    typealias NiceReturn = GetStickerUploadFormsResponse
    typealias FfiReturn = SignalGetStickerUploadFormsResponseFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalGetStickerUploadFormsResponseFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let pack_id = Result { try StringConverter.convertReturn(consuming: ffiValue.pack_id) }
        let manifest_upload_form = Result {
            try DerivedReturnConverterS3UploadFormInternal.convertReturn(consuming: ffiValue.manifest_upload_form)
        }
        let sticker_upload_forms = Result {
            try ArrayReturnConverter<
                DerivedReturnConverterS3UploadFormInternal, SignalOwnedBufferOfMaxAlignedS3UploadFormInternalFfiResult
            >.convertReturn(consuming: ffiValue.sticker_upload_forms)
        }

        return GetStickerUploadFormsResponse(
            packId: try pack_id.get(),
            manifestUploadForm: try manifest_upload_form.get(),
            stickerUploadForms: try sticker_upload_forms.get()
        )
    }
}

internal enum DerivedReturnConverterLinkedDeviceInternal: NiceReturnConverter {
    typealias NiceReturn = LinkedDevice
    typealias FfiReturn = SignalLinkedDeviceInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalLinkedDeviceInternalFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let id = Result { try DeviceIdConverter.convertReturn(consuming: ffiValue.id) }
        let encrypted_name = Result { try DataConverter.convertReturn(consuming: ffiValue.encrypted_name) }
        let last_seen = Result { try TimestampConverter.convertReturn(consuming: ffiValue.last_seen) }
        let registration_id = Result {
            try IdentityResultConverter<UInt16>.convertReturn(consuming: ffiValue.registration_id)
        }
        let created_at_ciphertext = Result {
            try DataConverter.convertReturn(consuming: ffiValue.created_at_ciphertext)
        }

        return LinkedDevice(
            id: try id.get(),
            encryptedName: try encrypted_name.get(),
            lastSeen: try last_seen.get(),
            registrationId: try registration_id.get(),
            createdAtCiphertext: try created_at_ciphertext.get()
        )
    }
}

internal enum DerivedReturnConverterListMediaItem: NiceReturnConverter {
    typealias NiceReturn = ListMediaItem
    typealias FfiReturn = SignalListMediaItemFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalListMediaItemFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let cdn = Result { try IdentityResultConverter<Int32>.convertReturn(consuming: ffiValue.cdn) }
        let media_id = Result {
            try FixedByteArrayConverter<FixedByteArrayHelper15>.convertReturn(consuming: ffiValue.media_id)
        }
        let object_length = Result {
            try IdentityResultConverter<Int64>.convertReturn(consuming: ffiValue.object_length)
        }

        return ListMediaItem(cdn: try cdn.get(), mediaId: try media_id.get(), objectLength: try object_length.get())
    }
}

internal enum DerivedReturnConverterListMediaResponse: NiceReturnConverter {
    typealias NiceReturn = ListMediaResponse
    typealias FfiReturn = SignalListMediaResponseFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalListMediaResponseFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let items = Result {
            try ArrayReturnConverter<
                DerivedReturnConverterListMediaItem, SignalOwnedBufferOfMaxAlignedListMediaItemFfiResult
            >.convertReturn(consuming: ffiValue.items)
        }
        let backup_dir = Result { try StringConverter.convertReturn(consuming: ffiValue.backup_dir) }
        let media_dir = Result { try StringConverter.convertReturn(consuming: ffiValue.media_dir) }
        let cursor = Result { try OptionalStringConverter.convertReturn(consuming: ffiValue.cursor) }

        return ListMediaResponse(
            items: try items.get(),
            backupDir: try backup_dir.get(),
            mediaDir: try media_dir.get(),
            cursor: try cursor.get()
        )
    }
}

internal enum DerivedReturnConverterPaymentProviderInternal: NiceReturnConverter {
    typealias NiceReturn = PaymentProvider
    typealias FfiReturn = SignalPaymentProviderInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalPaymentProviderInternalFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalPaymentProviderInternalFfiResultGooglePlayBilling:
            return PaymentProvider.googlePlayBilling
        case SignalPaymentProviderInternalFfiResultAppleAppStore:
            return PaymentProvider.appleAppStore
        case SignalPaymentProviderInternalFfiResultStripe:
            return PaymentProvider.stripe
        case SignalPaymentProviderInternalFfiResultBraintree:
            return PaymentProvider.braintree
        default:
            throw SignalError.internalError("Unexpected enum tag for PaymentProviderInternal: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterProfile: NiceReturnConverter {
    typealias NiceReturn = Profile
    typealias FfiReturn = SignalProfileFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalProfileFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let given_name = Result { try StringConverter.convertReturn(consuming: ffiValue.given_name) }
        let family_name = Result { try StringConverter.convertReturn(consuming: ffiValue.family_name) }
        let about = Result { try StringConverter.convertReturn(consuming: ffiValue.about) }
        let about_emoji = Result { try StringConverter.convertReturn(consuming: ffiValue.about_emoji) }
        let avatar = Result {
            try OptionalReturnConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.convertReturn(
                consuming: ffiValue.avatar
            )
        }
        let phone_number_sharing = Result {
            try OptionalReturnConverter<IdentityResultConverter<Bool>, SignalOptionalOfbool>.convertReturn(
                consuming: ffiValue.phone_number_sharing
            )
        }
        let payment_address = Result {
            try OptionalReturnConverter<DataConverter, SignalOptionalOfOwnedBuffer>.convertReturn(
                consuming: ffiValue.payment_address
            )
        }
        let badge_ids = Result {
            try ArrayReturnConverter<StringConverter, SignalOwnedBufferOfMaxAlignedCStringPtr>.convertReturn(
                consuming: ffiValue.badge_ids
            )
        }

        return Profile(
            givenName: try given_name.get(),
            familyName: try family_name.get(),
            about: try about.get(),
            aboutEmoji: try about_emoji.get(),
            avatar: try avatar.get(),
            phoneNumberSharing: try phone_number_sharing.get(),
            paymentAddress: try payment_address.get(),
            badgeIds: try badge_ids.get()
        )
    }
}

internal enum DerivedReturnConverterProfileFieldWithMaxLength: NiceReturnConverter {
    typealias NiceReturn = ProfileFieldWithMaxLength
    typealias FfiReturn = SignalProfileFieldWithMaxLengthFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalProfileFieldWithMaxLengthFfiResult(0)
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue
        switch ffiTag {
        case SignalProfileFieldWithMaxLengthFfiResultGivenName:
            return ProfileFieldWithMaxLength.givenName
        case SignalProfileFieldWithMaxLengthFfiResultFamilyName:
            return ProfileFieldWithMaxLength.familyName
        case SignalProfileFieldWithMaxLengthFfiResultAbout:
            return ProfileFieldWithMaxLength.about
        case SignalProfileFieldWithMaxLengthFfiResultAboutEmoji:
            return ProfileFieldWithMaxLength.aboutEmoji
        case SignalProfileFieldWithMaxLengthFfiResultAvatar:
            return ProfileFieldWithMaxLength.avatar
        case SignalProfileFieldWithMaxLengthFfiResultPaymentAddress:
            return ProfileFieldWithMaxLength.paymentAddress
        default:
            throw SignalError.internalError("Unexpected enum tag for ProfileFieldWithMaxLength: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterProfileValidationErrorInternal: NiceReturnConverter {
    typealias NiceReturn = ProfileValidationErrorInternal
    typealias FfiReturn = SignalProfileValidationErrorInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalProfileValidationErrorInternalFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {
        let ffiTag = ffiValue.tag
        switch ffiTag {
        case SignalProfileValidationErrorInternalFfiResultFieldTooLong:
            let field = Result {
                try DerivedReturnConverterProfileFieldWithMaxLength.convertReturn(
                    consuming: ffiValue.field_too_long.field
                )
            }
            let len = Result {
                try IdentityResultConverter<Int32>.convertReturn(
                    consuming: ffiValue.field_too_long.len
                )
            }
            let max_len = Result {
                try IdentityResultConverter<Int32>.convertReturn(
                    consuming: ffiValue.field_too_long.max_len
                )
            }
            return ProfileValidationErrorInternal.fieldTooLong(
                field: try field.get(),
                len: try len.get(),
                maxLen: try max_len.get()
            )
        case SignalProfileValidationErrorInternalFfiResultGivenNameEmpty:
            return ProfileValidationErrorInternal.givenNameEmpty
        default:
            throw SignalError.internalError("Unexpected enum tag for ProfileValidationErrorInternal: \(ffiTag)")
        }
    }
}

internal enum DerivedReturnConverterS3UploadFormInternal: NiceReturnConverter {
    typealias NiceReturn = S3UploadForm
    typealias FfiReturn = SignalS3UploadFormInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalS3UploadFormInternalFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let key = Result { try StringConverter.convertReturn(consuming: ffiValue.key) }
        let credential = Result { try StringConverter.convertReturn(consuming: ffiValue.credential) }
        let acl = Result { try StringConverter.convertReturn(consuming: ffiValue.acl) }
        let algorithm = Result { try StringConverter.convertReturn(consuming: ffiValue.algorithm) }
        let date = Result { try StringConverter.convertReturn(consuming: ffiValue.date) }
        let policy = Result { try StringConverter.convertReturn(consuming: ffiValue.policy) }
        let signature = Result { try StringConverter.convertReturn(consuming: ffiValue.signature) }

        return S3UploadForm(
            key: try key.get(),
            credential: try credential.get(),
            acl: try acl.get(),
            algorithm: try algorithm.get(),
            date: try date.get(),
            policy: try policy.get(),
            signature: try signature.get()
        )
    }
}

internal enum DerivedReturnConverterStartMfaVerificationResponse: NiceReturnConverter {
    typealias NiceReturn = StartMfaVerificationResponse
    typealias FfiReturn = SignalStartMfaVerificationResponseFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalStartMfaVerificationResponseFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let has_totp = Result { try IdentityResultConverter<Bool>.convertReturn(consuming: ffiValue.has_totp) }
        let webauthn_params = Result {
            try OptionalReturnConverter<
                DerivedReturnConverterBridgeWebAuthnAuthenticationParameters,
                SignalOptionalOfBridgeWebAuthnAuthenticationParametersFfiResult
            >.convertReturn(consuming: ffiValue.webauthn_params)
        }

        return StartMfaVerificationResponse(hasTotp: try has_totp.get(), webauthnParams: try webauthn_params.get())
    }
}

internal enum DerivedReturnConverterTaggedBadges: NiceReturnConverter {
    typealias NiceReturn = TaggedBadges
    typealias FfiReturn = SignalTaggedBadgesFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalTaggedBadgesFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let badges = Result {
            try StringMapReturnConverter<
                DerivedReturnConverterBadge, SignalOwnedBufferOfMaxAlignedPairOfCStringPtrBadgeFfiResult,
                SignalPairOfCStringPtrBadgeFfiResult
            >.convertReturn(consuming: ffiValue.badges)
        }
        let etag = Result { try DataConverter.convertReturn(consuming: ffiValue.etag) }

        return TaggedBadges(badges: try badges.get(), etag: try etag.get())
    }
}

internal enum DerivedArgConverterBadgeVisibility: NiceArgConverter {
    typealias NiceArg = BadgeVisibility
    typealias FfiArg = SignalBadgeVisibilityFfiArg
    typealias KeepAlive = ()
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .doNotSet:
            return (SignalBadgeVisibilityFfiArgDoNotSet, nil)

        case .setVisible:
            return (SignalBadgeVisibilityFfiArgSetVisible, nil)

        case .setPrimary:
            return (SignalBadgeVisibilityFfiArgSetPrimary, nil)

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .doNotSet:
            return try niceThunk(SignalBadgeVisibilityFfiArgDoNotSet)

        case .setVisible:
            return try niceThunk(SignalBadgeVisibilityFfiArgSetVisible)

        case .setPrimary:
            return try niceThunk(SignalBadgeVisibilityFfiArgSetPrimary)

        }
    }
}

internal enum BridgeChallengeAnswerArgConverterKeepAlive {
    case push((StringConverter.KeepAlive?))
    case captcha((StringConverter.KeepAlive?))
}

internal enum DerivedArgConverterBridgeChallengeAnswer: NiceArgConverter {
    typealias NiceArg = ChallengeAnswer
    typealias FfiArg = SignalBridgeChallengeAnswerFfiArg
    typealias KeepAlive = BridgeChallengeAnswerArgConverterKeepAlive
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {
        case .push(
            let _0,
        ):

            let (_0_ffi, _0_keepalive):
                (
                    StringConverter.FfiArg,
                    StringConverter.KeepAlive?,
                ) = StringConverter.convertArg(_0)

            let ffiStructArg = SignalBridgeChallengeAnswerFfiArgSignalPush_Body(_0: _0_ffi, )
            let ffiStructKeepAlive: (StringConverter.KeepAlive?, )? =
                (_0_keepalive != nil || false)
                ? (_0_keepalive,)
                : nil

            return (
                SignalBridgeChallengeAnswerFfiArg.init(
                    tag: SignalBridgeChallengeAnswerFfiArgPush,
                    .init(push: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .push($0) },
            )

        case .captcha(
            let _0,
        ):

            let (_0_ffi, _0_keepalive):
                (
                    StringConverter.FfiArg,
                    StringConverter.KeepAlive?,
                ) = StringConverter.convertArg(_0)

            let ffiStructArg = SignalBridgeChallengeAnswerFfiArgSignalCaptcha_Body(_0: _0_ffi, )
            let ffiStructKeepAlive: (StringConverter.KeepAlive?, )? =
                (_0_keepalive != nil || false)
                ? (_0_keepalive,)
                : nil

            return (
                SignalBridgeChallengeAnswerFfiArg.init(
                    tag: SignalBridgeChallengeAnswerFfiArgCaptcha,
                    .init(captcha: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .captcha($0) },
            )

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .push(
            let _0,
        ):

            return try StringConverter.convertArgBorrowed(_0) {
                ffi__0 in

                return try niceThunk(
                    SignalBridgeChallengeAnswerFfiArg.init(
                        tag: SignalBridgeChallengeAnswerFfiArgPush,
                        .init(
                            push:
                                SignalBridgeChallengeAnswerFfiArgSignalPush_Body(
                                    _0: ffi__0,
                                )
                        ),
                    )
                )

            }

        case .captcha(
            let _0,
        ):

            return try StringConverter.convertArgBorrowed(_0) {
                ffi__0 in

                return try niceThunk(
                    SignalBridgeChallengeAnswerFfiArg.init(
                        tag: SignalBridgeChallengeAnswerFfiArgCaptcha,
                        .init(
                            captcha:
                                SignalBridgeChallengeAnswerFfiArgSignalCaptcha_Body(
                                    _0: ffi__0,
                                )
                        ),
                    )
                )

            }

        }
    }
}

internal enum DerivedArgConverterBridgeCopyBackupMediaItem: NiceArgConverter {
    typealias NiceArg = BridgeCopyBackupMediaItem
    typealias FfiArg = SignalBridgeCopyBackupMediaItemFfiArg

    typealias KeepAlive = (
        IdentityArgConverter<Int32>.KeepAlive?, StringConverter.KeepAlive?, IdentityArgConverter<Int64>.KeepAlive?,
        FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?,
        FixedByteArrayConverter<FixedByteArrayHelper64>.KeepAlive?,
    )
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        let source_attachment_cdn = niceArg.sourceAttachmentCdn
        let source_key = niceArg.sourceKey
        let object_length = niceArg.objectLength
        let media_id = niceArg.mediaId
        let encryption_key = niceArg.encryptionKey

        let (source_attachment_cdn_ffi, source_attachment_cdn_keepalive):
            (
                IdentityArgConverter<Int32>.FfiArg,
                IdentityArgConverter<Int32>.KeepAlive?,
            ) = IdentityArgConverter<Int32>.convertArg(source_attachment_cdn)
        let (source_key_ffi, source_key_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(source_key)
        let (object_length_ffi, object_length_keepalive):
            (
                IdentityArgConverter<Int64>.FfiArg,
                IdentityArgConverter<Int64>.KeepAlive?,
            ) = IdentityArgConverter<Int64>.convertArg(object_length)
        let (media_id_ffi, media_id_keepalive):
            (
                FixedByteArrayConverter<FixedByteArrayHelper15>.FfiArg,
                FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?,
            ) = FixedByteArrayConverter<FixedByteArrayHelper15>.convertArg(media_id)
        let (encryption_key_ffi, encryption_key_keepalive):
            (
                FixedByteArrayConverter<FixedByteArrayHelper64>.FfiArg,
                FixedByteArrayConverter<FixedByteArrayHelper64>.KeepAlive?,
            ) = FixedByteArrayConverter<FixedByteArrayHelper64>.convertArg(encryption_key)

        let ffiStructArg = FfiArg(
            source_attachment_cdn: source_attachment_cdn_ffi,
            source_key: source_key_ffi,
            object_length: object_length_ffi,
            media_id: media_id_ffi,
            encryption_key: encryption_key_ffi,
        )
        let ffiStructKeepAlive:
            (
                IdentityArgConverter<Int32>.KeepAlive?, StringConverter.KeepAlive?,
                IdentityArgConverter<Int64>.KeepAlive?, FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?,
                FixedByteArrayConverter<FixedByteArrayHelper64>.KeepAlive?,
            )? =
                (source_attachment_cdn_keepalive != nil || source_key_keepalive != nil || object_length_keepalive != nil
                    || media_id_keepalive != nil || encryption_key_keepalive != nil || false)
                ? (
                    source_attachment_cdn_keepalive, source_key_keepalive, object_length_keepalive, media_id_keepalive,
                    encryption_key_keepalive,
                )
                : nil

        return (ffiStructArg, ffiStructKeepAlive)
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        let source_attachment_cdn = niceArg.sourceAttachmentCdn
        let source_key = niceArg.sourceKey
        let object_length = niceArg.objectLength
        let media_id = niceArg.mediaId
        let encryption_key = niceArg.encryptionKey

        return try IdentityArgConverter<Int32>.convertArgBorrowed(source_attachment_cdn) {
            ffi_source_attachment_cdn in
            return try StringConverter.convertArgBorrowed(source_key) {
                ffi_source_key in
                return try IdentityArgConverter<Int64>.convertArgBorrowed(object_length) {
                    ffi_object_length in
                    return try FixedByteArrayConverter<FixedByteArrayHelper15>.convertArgBorrowed(media_id) {
                        ffi_media_id in
                        return try FixedByteArrayConverter<FixedByteArrayHelper64>.convertArgBorrowed(encryption_key) {
                            ffi_encryption_key in

                            return try niceThunk(
                                FfiArg(
                                    source_attachment_cdn: ffi_source_attachment_cdn,
                                    source_key: ffi_source_key,
                                    object_length: ffi_object_length,
                                    media_id: ffi_media_id,
                                    encryption_key: ffi_encryption_key,
                                )
                            )

                        }
                    }
                }
            }
        }

    }
}

internal enum DerivedArgConverterBridgeDeleteBackupMediaItem: NiceArgConverter {
    typealias NiceArg = BridgeDeleteBackupMediaItem
    typealias FfiArg = SignalBridgeDeleteBackupMediaItemFfiArg

    typealias KeepAlive = (
        FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?, IdentityArgConverter<Int32>.KeepAlive?,
    )
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        let media_id = niceArg.mediaId
        let cdn = niceArg.cdn

        let (media_id_ffi, media_id_keepalive):
            (
                FixedByteArrayConverter<FixedByteArrayHelper15>.FfiArg,
                FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?,
            ) = FixedByteArrayConverter<FixedByteArrayHelper15>.convertArg(media_id)
        let (cdn_ffi, cdn_keepalive):
            (
                IdentityArgConverter<Int32>.FfiArg,
                IdentityArgConverter<Int32>.KeepAlive?,
            ) = IdentityArgConverter<Int32>.convertArg(cdn)

        let ffiStructArg = FfiArg(media_id: media_id_ffi, cdn: cdn_ffi, )
        let ffiStructKeepAlive:
            (FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?, IdentityArgConverter<Int32>.KeepAlive?, )? =
                (media_id_keepalive != nil || cdn_keepalive != nil || false)
                ? (media_id_keepalive, cdn_keepalive,)
                : nil

        return (ffiStructArg, ffiStructKeepAlive)
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        let media_id = niceArg.mediaId
        let cdn = niceArg.cdn

        return try FixedByteArrayConverter<FixedByteArrayHelper15>.convertArgBorrowed(media_id) {
            ffi_media_id in
            return try IdentityArgConverter<Int32>.convertArgBorrowed(cdn) {
                ffi_cdn in

                return try niceThunk(
                    FfiArg(
                        media_id: ffi_media_id,
                        cdn: ffi_cdn,
                    )
                )

            }
        }

    }
}

internal enum BridgeMfaVerificationCredentialArgConverterKeepAlive {
    case totp((IdentityArgConverter<Int32>.KeepAlive?))
    case webAuthn((StringConverter.KeepAlive?))
}

internal enum DerivedArgConverterBridgeMfaVerificationCredential: NiceArgConverter {
    typealias NiceArg = BridgeMfaVerificationCredential
    typealias FfiArg = SignalBridgeMfaVerificationCredentialFfiArg
    typealias KeepAlive = BridgeMfaVerificationCredentialArgConverterKeepAlive
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {
        case .totp(
            let password,
        ):

            let (password_ffi, password_keepalive):
                (
                    IdentityArgConverter<Int32>.FfiArg,
                    IdentityArgConverter<Int32>.KeepAlive?,
                ) = IdentityArgConverter<Int32>.convertArg(password)

            let ffiStructArg = SignalBridgeMfaVerificationCredentialFfiArgSignalTotp_Body(password: password_ffi, )
            let ffiStructKeepAlive: (IdentityArgConverter<Int32>.KeepAlive?, )? =
                (password_keepalive != nil || false)
                ? (password_keepalive,)
                : nil

            return (
                SignalBridgeMfaVerificationCredentialFfiArg.init(
                    tag: SignalBridgeMfaVerificationCredentialFfiArgTotp,
                    .init(totp: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .totp($0) },
            )

        case .webAuthn(
            let json,
        ):

            let (json_ffi, json_keepalive):
                (
                    StringConverter.FfiArg,
                    StringConverter.KeepAlive?,
                ) = StringConverter.convertArg(json)

            let ffiStructArg = SignalBridgeMfaVerificationCredentialFfiArgSignalWebAuthn_Body(json: json_ffi, )
            let ffiStructKeepAlive: (StringConverter.KeepAlive?, )? =
                (json_keepalive != nil || false)
                ? (json_keepalive,)
                : nil

            return (
                SignalBridgeMfaVerificationCredentialFfiArg.init(
                    tag: SignalBridgeMfaVerificationCredentialFfiArgWebAuthn,
                    .init(web_authn: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .webAuthn($0) },
            )

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .totp(
            let password,
        ):

            return try IdentityArgConverter<Int32>.convertArgBorrowed(password) {
                ffi_password in

                return try niceThunk(
                    SignalBridgeMfaVerificationCredentialFfiArg.init(
                        tag: SignalBridgeMfaVerificationCredentialFfiArgTotp,
                        .init(
                            totp:
                                SignalBridgeMfaVerificationCredentialFfiArgSignalTotp_Body(
                                    password: ffi_password,
                                )
                        ),
                    )
                )

            }

        case .webAuthn(
            let json,
        ):

            return try StringConverter.convertArgBorrowed(json) {
                ffi_json in

                return try niceThunk(
                    SignalBridgeMfaVerificationCredentialFfiArg.init(
                        tag: SignalBridgeMfaVerificationCredentialFfiArgWebAuthn,
                        .init(
                            web_authn:
                                SignalBridgeMfaVerificationCredentialFfiArgSignalWebAuthn_Body(
                                    json: ffi_json,
                                )
                        ),
                    )
                )

            }

        }
    }
}

internal enum DerivedArgConverterCallQualitySurveyInternal: NiceArgConverter {
    typealias NiceArg = CallQualitySurvey
    typealias FfiArg = SignalCallQualitySurveyInternalFfiArg

    typealias KeepAlive = (
        IdentityArgConverter<Bool>.KeepAlive?,
        ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.KeepAlive?,
        OptionalStringConverter.KeepAlive?, OptionalStringConverter.KeepAlive?, TimestampConverter.KeepAlive?,
        TimestampConverter.KeepAlive?, StringConverter.KeepAlive?, IdentityArgConverter<Bool>.KeepAlive?,
        StringConverter.KeepAlive?, OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
        OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
        OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
    )
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        let user_satisfied = niceArg.userSatisfied
        let call_quality_issues = niceArg.callQualityIssues
        let additional_issues_description = niceArg.additionalIssuesDescription
        let debug_log_url = niceArg.debugLogUrl
        let start_timestamp = niceArg.startTimestamp
        let end_timestamp = niceArg.endTimestamp
        let call_type = niceArg.callType
        let success = niceArg.success
        let call_end_reason = niceArg.callEndReason
        let connection_rtt_median = niceArg.connectionRttMedian
        let audio_rtt_median = niceArg.audioRttMedian
        let video_rtt_median = niceArg.videoRttMedian
        let audio_recv_jitter_median = niceArg.audioRecvJitterMedian
        let video_recv_jitter_median = niceArg.videoRecvJitterMedian
        let audio_send_jitter_median = niceArg.audioSendJitterMedian
        let video_send_jitter_median = niceArg.videoSendJitterMedian
        let audio_recv_packet_loss_fraction = niceArg.audioRecvPacketLossFraction
        let video_recv_packet_loss_fraction = niceArg.videoRecvPacketLossFraction
        let audio_send_packet_loss_fraction = niceArg.audioSendPacketLossFraction
        let video_send_packet_loss_fraction = niceArg.videoSendPacketLossFraction
        let call_telemetry = niceArg.callTelemetry
        let call_id_hash = niceArg.callIdHash

        let (user_satisfied_ffi, user_satisfied_keepalive):
            (
                IdentityArgConverter<Bool>.FfiArg,
                IdentityArgConverter<Bool>.KeepAlive?,
            ) = IdentityArgConverter<Bool>.convertArg(user_satisfied)
        let (call_quality_issues_ffi, call_quality_issues_keepalive):
            (
                ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.FfiArg,
                ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.KeepAlive?,
            ) = ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.convertArg(call_quality_issues)
        let (additional_issues_description_ffi, additional_issues_description_keepalive):
            (
                OptionalStringConverter.FfiArg,
                OptionalStringConverter.KeepAlive?,
            ) = OptionalStringConverter.convertArg(additional_issues_description)
        let (debug_log_url_ffi, debug_log_url_keepalive):
            (
                OptionalStringConverter.FfiArg,
                OptionalStringConverter.KeepAlive?,
            ) = OptionalStringConverter.convertArg(debug_log_url)
        let (start_timestamp_ffi, start_timestamp_keepalive):
            (
                TimestampConverter.FfiArg,
                TimestampConverter.KeepAlive?,
            ) = TimestampConverter.convertArg(start_timestamp)
        let (end_timestamp_ffi, end_timestamp_keepalive):
            (
                TimestampConverter.FfiArg,
                TimestampConverter.KeepAlive?,
            ) = TimestampConverter.convertArg(end_timestamp)
        let (call_type_ffi, call_type_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(call_type)
        let (success_ffi, success_keepalive):
            (
                IdentityArgConverter<Bool>.FfiArg,
                IdentityArgConverter<Bool>.KeepAlive?,
            ) = IdentityArgConverter<Bool>.convertArg(success)
        let (call_end_reason_ffi, call_end_reason_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(call_end_reason)
        let (connection_rtt_median_ffi, connection_rtt_median_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(connection_rtt_median)
        let (audio_rtt_median_ffi, audio_rtt_median_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(audio_rtt_median)
        let (video_rtt_median_ffi, video_rtt_median_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(video_rtt_median)
        let (audio_recv_jitter_median_ffi, audio_recv_jitter_median_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                audio_recv_jitter_median
            )
        let (video_recv_jitter_median_ffi, video_recv_jitter_median_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                video_recv_jitter_median
            )
        let (audio_send_jitter_median_ffi, audio_send_jitter_median_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                audio_send_jitter_median
            )
        let (video_send_jitter_median_ffi, video_send_jitter_median_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                video_send_jitter_median
            )
        let (audio_recv_packet_loss_fraction_ffi, audio_recv_packet_loss_fraction_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                audio_recv_packet_loss_fraction
            )
        let (video_recv_packet_loss_fraction_ffi, video_recv_packet_loss_fraction_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                video_recv_packet_loss_fraction
            )
        let (audio_send_packet_loss_fraction_ffi, audio_send_packet_loss_fraction_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                audio_send_packet_loss_fraction
            )
        let (video_send_packet_loss_fraction_ffi, video_send_packet_loss_fraction_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.convertArg(
                video_send_packet_loss_fraction
            )
        let (call_telemetry_ffi, call_telemetry_keepalive):
            (
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.FfiArg,
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
            ) = OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.convertArg(call_telemetry)
        let (call_id_hash_ffi, call_id_hash_keepalive):
            (
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.FfiArg,
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
            ) = OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.convertArg(call_id_hash)

        let ffiStructArg = FfiArg(
            user_satisfied: user_satisfied_ffi,
            call_quality_issues: call_quality_issues_ffi,
            additional_issues_description: additional_issues_description_ffi,
            debug_log_url: debug_log_url_ffi,
            start_timestamp: start_timestamp_ffi,
            end_timestamp: end_timestamp_ffi,
            call_type: call_type_ffi,
            success: success_ffi,
            call_end_reason: call_end_reason_ffi,
            connection_rtt_median: connection_rtt_median_ffi,
            audio_rtt_median: audio_rtt_median_ffi,
            video_rtt_median: video_rtt_median_ffi,
            audio_recv_jitter_median: audio_recv_jitter_median_ffi,
            video_recv_jitter_median: video_recv_jitter_median_ffi,
            audio_send_jitter_median: audio_send_jitter_median_ffi,
            video_send_jitter_median: video_send_jitter_median_ffi,
            audio_recv_packet_loss_fraction: audio_recv_packet_loss_fraction_ffi,
            video_recv_packet_loss_fraction: video_recv_packet_loss_fraction_ffi,
            audio_send_packet_loss_fraction: audio_send_packet_loss_fraction_ffi,
            video_send_packet_loss_fraction: video_send_packet_loss_fraction_ffi,
            call_telemetry: call_telemetry_ffi,
            call_id_hash: call_id_hash_ffi,
        )
        let ffiStructKeepAlive:
            (
                IdentityArgConverter<Bool>.KeepAlive?,
                ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.KeepAlive?,
                OptionalStringConverter.KeepAlive?, OptionalStringConverter.KeepAlive?, TimestampConverter.KeepAlive?,
                TimestampConverter.KeepAlive?, StringConverter.KeepAlive?, IdentityArgConverter<Bool>.KeepAlive?,
                StringConverter.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Float>, SignalOptionalOff32>.KeepAlive?,
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
            )? =
                (user_satisfied_keepalive != nil || call_quality_issues_keepalive != nil
                    || additional_issues_description_keepalive != nil || debug_log_url_keepalive != nil
                    || start_timestamp_keepalive != nil || end_timestamp_keepalive != nil || call_type_keepalive != nil
                    || success_keepalive != nil || call_end_reason_keepalive != nil
                    || connection_rtt_median_keepalive != nil || audio_rtt_median_keepalive != nil
                    || video_rtt_median_keepalive != nil || audio_recv_jitter_median_keepalive != nil
                    || video_recv_jitter_median_keepalive != nil || audio_send_jitter_median_keepalive != nil
                    || video_send_jitter_median_keepalive != nil || audio_recv_packet_loss_fraction_keepalive != nil
                    || video_recv_packet_loss_fraction_keepalive != nil
                    || audio_send_packet_loss_fraction_keepalive != nil
                    || video_send_packet_loss_fraction_keepalive != nil || call_telemetry_keepalive != nil
                    || call_id_hash_keepalive != nil || false)
                ? (
                    user_satisfied_keepalive, call_quality_issues_keepalive, additional_issues_description_keepalive,
                    debug_log_url_keepalive, start_timestamp_keepalive, end_timestamp_keepalive, call_type_keepalive,
                    success_keepalive, call_end_reason_keepalive, connection_rtt_median_keepalive,
                    audio_rtt_median_keepalive, video_rtt_median_keepalive, audio_recv_jitter_median_keepalive,
                    video_recv_jitter_median_keepalive, audio_send_jitter_median_keepalive,
                    video_send_jitter_median_keepalive, audio_recv_packet_loss_fraction_keepalive,
                    video_recv_packet_loss_fraction_keepalive, audio_send_packet_loss_fraction_keepalive,
                    video_send_packet_loss_fraction_keepalive, call_telemetry_keepalive, call_id_hash_keepalive,
                )
                : nil

        return (ffiStructArg, ffiStructKeepAlive)
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        let user_satisfied = niceArg.userSatisfied
        let call_quality_issues = niceArg.callQualityIssues
        let additional_issues_description = niceArg.additionalIssuesDescription
        let debug_log_url = niceArg.debugLogUrl
        let start_timestamp = niceArg.startTimestamp
        let end_timestamp = niceArg.endTimestamp
        let call_type = niceArg.callType
        let success = niceArg.success
        let call_end_reason = niceArg.callEndReason
        let connection_rtt_median = niceArg.connectionRttMedian
        let audio_rtt_median = niceArg.audioRttMedian
        let video_rtt_median = niceArg.videoRttMedian
        let audio_recv_jitter_median = niceArg.audioRecvJitterMedian
        let video_recv_jitter_median = niceArg.videoRecvJitterMedian
        let audio_send_jitter_median = niceArg.audioSendJitterMedian
        let video_send_jitter_median = niceArg.videoSendJitterMedian
        let audio_recv_packet_loss_fraction = niceArg.audioRecvPacketLossFraction
        let video_recv_packet_loss_fraction = niceArg.videoRecvPacketLossFraction
        let audio_send_packet_loss_fraction = niceArg.audioSendPacketLossFraction
        let video_send_packet_loss_fraction = niceArg.videoSendPacketLossFraction
        let call_telemetry = niceArg.callTelemetry
        let call_id_hash = niceArg.callIdHash

        return try IdentityArgConverter<Bool>.convertArgBorrowed(user_satisfied) {
            ffi_user_satisfied in
            return try ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.convertArgBorrowed(
                call_quality_issues
            ) {
                ffi_call_quality_issues in
                return try OptionalStringConverter.convertArgBorrowed(additional_issues_description) {
                    ffi_additional_issues_description in
                    return try OptionalStringConverter.convertArgBorrowed(debug_log_url) {
                        ffi_debug_log_url in
                        return try TimestampConverter.convertArgBorrowed(start_timestamp) {
                            ffi_start_timestamp in
                            return try TimestampConverter.convertArgBorrowed(end_timestamp) {
                                ffi_end_timestamp in
                                return try StringConverter.convertArgBorrowed(call_type) {
                                    ffi_call_type in
                                    return try IdentityArgConverter<Bool>.convertArgBorrowed(success) {
                                        ffi_success in
                                        return try StringConverter.convertArgBorrowed(call_end_reason) {
                                            ffi_call_end_reason in
                                            return try OptionalArgConverter<
                                                IdentityArgConverter<Float>, SignalOptionalOff32
                                            >.convertArgBorrowed(connection_rtt_median) {
                                                ffi_connection_rtt_median in
                                                return try OptionalArgConverter<
                                                    IdentityArgConverter<Float>, SignalOptionalOff32
                                                >.convertArgBorrowed(audio_rtt_median) {
                                                    ffi_audio_rtt_median in
                                                    return try OptionalArgConverter<
                                                        IdentityArgConverter<Float>, SignalOptionalOff32
                                                    >.convertArgBorrowed(video_rtt_median) {
                                                        ffi_video_rtt_median in
                                                        return try OptionalArgConverter<
                                                            IdentityArgConverter<Float>, SignalOptionalOff32
                                                        >.convertArgBorrowed(audio_recv_jitter_median) {
                                                            ffi_audio_recv_jitter_median in
                                                            return try OptionalArgConverter<
                                                                IdentityArgConverter<Float>, SignalOptionalOff32
                                                            >.convertArgBorrowed(video_recv_jitter_median) {
                                                                ffi_video_recv_jitter_median in
                                                                return try OptionalArgConverter<
                                                                    IdentityArgConverter<Float>, SignalOptionalOff32
                                                                >.convertArgBorrowed(audio_send_jitter_median) {
                                                                    ffi_audio_send_jitter_median in
                                                                    return try OptionalArgConverter<
                                                                        IdentityArgConverter<Float>, SignalOptionalOff32
                                                                    >.convertArgBorrowed(video_send_jitter_median) {
                                                                        ffi_video_send_jitter_median in
                                                                        return try OptionalArgConverter<
                                                                            IdentityArgConverter<Float>,
                                                                            SignalOptionalOff32
                                                                        >.convertArgBorrowed(
                                                                            audio_recv_packet_loss_fraction
                                                                        ) {
                                                                            ffi_audio_recv_packet_loss_fraction in
                                                                            return try OptionalArgConverter<
                                                                                IdentityArgConverter<Float>,
                                                                                SignalOptionalOff32
                                                                            >.convertArgBorrowed(
                                                                                video_recv_packet_loss_fraction
                                                                            ) {
                                                                                ffi_video_recv_packet_loss_fraction in
                                                                                return try OptionalArgConverter<
                                                                                    IdentityArgConverter<Float>,
                                                                                    SignalOptionalOff32
                                                                                >.convertArgBorrowed(
                                                                                    audio_send_packet_loss_fraction
                                                                                ) {
                                                                                    ffi_audio_send_packet_loss_fraction
                                                                                    in
                                                                                    return try OptionalArgConverter<
                                                                                        IdentityArgConverter<Float>,
                                                                                        SignalOptionalOff32
                                                                                    >.convertArgBorrowed(
                                                                                        video_send_packet_loss_fraction
                                                                                    ) {
                                                                                        ffi_video_send_packet_loss_fraction
                                                                                        in
                                                                                        return try OptionalArgConverter<
                                                                                            DataConverter,
                                                                                            SignalOptionalOfBorrowedBuffer
                                                                                        >.convertArgBorrowed(
                                                                                            call_telemetry
                                                                                        ) {
                                                                                            ffi_call_telemetry in
                                                                                            return try
                                                                                                OptionalArgConverter<
                                                                                                    DataConverter,
                                                                                                    SignalOptionalOfBorrowedBuffer
                                                                                                >.convertArgBorrowed(
                                                                                                    call_id_hash
                                                                                                ) {
                                                                                                    ffi_call_id_hash in

                                                                                                    return
                                                                                                        try niceThunk(
                                                                                                            FfiArg(
                                                                                                                user_satisfied:
                                                                                                                    ffi_user_satisfied,
                                                                                                                call_quality_issues:
                                                                                                                    ffi_call_quality_issues,
                                                                                                                additional_issues_description:
                                                                                                                    ffi_additional_issues_description,
                                                                                                                debug_log_url:
                                                                                                                    ffi_debug_log_url,
                                                                                                                start_timestamp:
                                                                                                                    ffi_start_timestamp,
                                                                                                                end_timestamp:
                                                                                                                    ffi_end_timestamp,
                                                                                                                call_type:
                                                                                                                    ffi_call_type,
                                                                                                                success:
                                                                                                                    ffi_success,
                                                                                                                call_end_reason:
                                                                                                                    ffi_call_end_reason,
                                                                                                                connection_rtt_median:
                                                                                                                    ffi_connection_rtt_median,
                                                                                                                audio_rtt_median:
                                                                                                                    ffi_audio_rtt_median,
                                                                                                                video_rtt_median:
                                                                                                                    ffi_video_rtt_median,
                                                                                                                audio_recv_jitter_median:
                                                                                                                    ffi_audio_recv_jitter_median,
                                                                                                                video_recv_jitter_median:
                                                                                                                    ffi_video_recv_jitter_median,
                                                                                                                audio_send_jitter_median:
                                                                                                                    ffi_audio_send_jitter_median,
                                                                                                                video_send_jitter_median:
                                                                                                                    ffi_video_send_jitter_median,
                                                                                                                audio_recv_packet_loss_fraction:
                                                                                                                    ffi_audio_recv_packet_loss_fraction,
                                                                                                                video_recv_packet_loss_fraction:
                                                                                                                    ffi_video_recv_packet_loss_fraction,
                                                                                                                audio_send_packet_loss_fraction:
                                                                                                                    ffi_audio_send_packet_loss_fraction,
                                                                                                                video_send_packet_loss_fraction:
                                                                                                                    ffi_video_send_packet_loss_fraction,
                                                                                                                call_telemetry:
                                                                                                                    ffi_call_telemetry,
                                                                                                                call_id_hash:
                                                                                                                    ffi_call_id_hash,
                                                                                                            )
                                                                                                        )

                                                                                                }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

    }
}

internal enum DerivedArgConverterDeviceCapabilityInternal: NiceArgConverter {
    typealias NiceArg = DeviceCapability
    typealias FfiArg = SignalDeviceCapabilityInternalFfiArg
    typealias KeepAlive = ()
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .storage:
            return (SignalDeviceCapabilityInternalFfiArgStorage, nil)

        case .transfer:
            return (SignalDeviceCapabilityInternalFfiArgTransfer, nil)

        case .attachmentBackfill:
            return (SignalDeviceCapabilityInternalFfiArgAttachmentBackfill, nil)

        case .sparsePostQuantumRatchet:
            return (SignalDeviceCapabilityInternalFfiArgSparsePostQuantumRatchet, nil)

        case .profilesV2:
            return (SignalDeviceCapabilityInternalFfiArgProfilesV2, nil)

        case .usernameChangeSyncMessage:
            return (SignalDeviceCapabilityInternalFfiArgUsernameChangeSyncMessage, nil)

        case .optionalPhoneNumber:
            return (SignalDeviceCapabilityInternalFfiArgOptionalPhoneNumber, nil)

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .storage:
            return try niceThunk(SignalDeviceCapabilityInternalFfiArgStorage)

        case .transfer:
            return try niceThunk(SignalDeviceCapabilityInternalFfiArgTransfer)

        case .attachmentBackfill:
            return try niceThunk(SignalDeviceCapabilityInternalFfiArgAttachmentBackfill)

        case .sparsePostQuantumRatchet:
            return try niceThunk(SignalDeviceCapabilityInternalFfiArgSparsePostQuantumRatchet)

        case .profilesV2:
            return try niceThunk(SignalDeviceCapabilityInternalFfiArgProfilesV2)

        case .usernameChangeSyncMessage:
            return try niceThunk(SignalDeviceCapabilityInternalFfiArgUsernameChangeSyncMessage)

        case .optionalPhoneNumber:
            return try niceThunk(SignalDeviceCapabilityInternalFfiArgOptionalPhoneNumber)

        }
    }
}

internal enum DerivedArgConverterLoginReceiptLevel: NiceArgConverter {
    typealias NiceArg = LoginReceiptLevel
    typealias FfiArg = SignalLoginReceiptLevelFfiArg
    typealias KeepAlive = ()
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .normal:
            return (SignalLoginReceiptLevelFfiArgNormal, nil)

        case .sandbox:
            return (SignalLoginReceiptLevelFfiArgSandbox, nil)

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .normal:
            return try niceThunk(SignalLoginReceiptLevelFfiArgNormal)

        case .sandbox:
            return try niceThunk(SignalLoginReceiptLevelFfiArgSandbox)

        }
    }
}

internal enum DerivedArgConverterPaymentProviderInternal: NiceArgConverter {
    typealias NiceArg = PaymentProvider
    typealias FfiArg = SignalPaymentProviderInternalFfiArg
    typealias KeepAlive = ()
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {

        case .googlePlayBilling:
            return (SignalPaymentProviderInternalFfiArgGooglePlayBilling, nil)

        case .appleAppStore:
            return (SignalPaymentProviderInternalFfiArgAppleAppStore, nil)

        case .stripe:
            return (SignalPaymentProviderInternalFfiArgStripe, nil)

        case .braintree:
            return (SignalPaymentProviderInternalFfiArgBraintree, nil)

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .googlePlayBilling:
            return try niceThunk(SignalPaymentProviderInternalFfiArgGooglePlayBilling)

        case .appleAppStore:
            return try niceThunk(SignalPaymentProviderInternalFfiArgAppleAppStore)

        case .stripe:
            return try niceThunk(SignalPaymentProviderInternalFfiArgStripe)

        case .braintree:
            return try niceThunk(SignalPaymentProviderInternalFfiArgBraintree)

        }
    }
}

internal enum DerivedArgConverterProfile: NiceArgConverter {
    typealias NiceArg = Profile
    typealias FfiArg = SignalProfileFfiArg

    typealias KeepAlive = (
        StringConverter.KeepAlive?, StringConverter.KeepAlive?, StringConverter.KeepAlive?, StringConverter.KeepAlive?,
        OptionalArgConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.KeepAlive?,
        OptionalArgConverter<IdentityArgConverter<Bool>, SignalOptionalOfbool>.KeepAlive?,
        OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
        ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.KeepAlive?,
    )
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        let given_name = niceArg.givenName
        let family_name = niceArg.familyName
        let about = niceArg.about
        let about_emoji = niceArg.aboutEmoji
        let avatar = niceArg.avatar
        let phone_number_sharing = niceArg.phoneNumberSharing
        let payment_address = niceArg.paymentAddress
        let badge_ids = niceArg.badgeIds

        let (given_name_ffi, given_name_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(given_name)
        let (family_name_ffi, family_name_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(family_name)
        let (about_ffi, about_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(about)
        let (about_emoji_ffi, about_emoji_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(about_emoji)
        let (avatar_ffi, avatar_keepalive):
            (
                OptionalArgConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.FfiArg,
                OptionalArgConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.KeepAlive?,
            ) = OptionalArgConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.convertArg(avatar)
        let (phone_number_sharing_ffi, phone_number_sharing_keepalive):
            (
                OptionalArgConverter<IdentityArgConverter<Bool>, SignalOptionalOfbool>.FfiArg,
                OptionalArgConverter<IdentityArgConverter<Bool>, SignalOptionalOfbool>.KeepAlive?,
            ) = OptionalArgConverter<IdentityArgConverter<Bool>, SignalOptionalOfbool>.convertArg(phone_number_sharing)
        let (payment_address_ffi, payment_address_keepalive):
            (
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.FfiArg,
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
            ) = OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.convertArg(payment_address)
        let (badge_ids_ffi, badge_ids_keepalive):
            (
                ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.FfiArg,
                ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.KeepAlive?,
            ) = ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.convertArg(badge_ids)

        let ffiStructArg = FfiArg(
            given_name: given_name_ffi,
            family_name: family_name_ffi,
            about: about_ffi,
            about_emoji: about_emoji_ffi,
            avatar: avatar_ffi,
            phone_number_sharing: phone_number_sharing_ffi,
            payment_address: payment_address_ffi,
            badge_ids: badge_ids_ffi,
        )
        let ffiStructKeepAlive:
            (
                StringConverter.KeepAlive?, StringConverter.KeepAlive?, StringConverter.KeepAlive?,
                StringConverter.KeepAlive?,
                OptionalArgConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.KeepAlive?,
                OptionalArgConverter<IdentityArgConverter<Bool>, SignalOptionalOfbool>.KeepAlive?,
                OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.KeepAlive?,
                ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.KeepAlive?,
            )? =
                (given_name_keepalive != nil || family_name_keepalive != nil || about_keepalive != nil
                    || about_emoji_keepalive != nil || avatar_keepalive != nil || phone_number_sharing_keepalive != nil
                    || payment_address_keepalive != nil || badge_ids_keepalive != nil || false)
                ? (
                    given_name_keepalive, family_name_keepalive, about_keepalive, about_emoji_keepalive,
                    avatar_keepalive, phone_number_sharing_keepalive, payment_address_keepalive, badge_ids_keepalive,
                )
                : nil

        return (ffiStructArg, ffiStructKeepAlive)
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        let given_name = niceArg.givenName
        let family_name = niceArg.familyName
        let about = niceArg.about
        let about_emoji = niceArg.aboutEmoji
        let avatar = niceArg.avatar
        let phone_number_sharing = niceArg.phoneNumberSharing
        let payment_address = niceArg.paymentAddress
        let badge_ids = niceArg.badgeIds

        return try StringConverter.convertArgBorrowed(given_name) {
            ffi_given_name in
            return try StringConverter.convertArgBorrowed(family_name) {
                ffi_family_name in
                return try StringConverter.convertArgBorrowed(about) {
                    ffi_about in
                    return try StringConverter.convertArgBorrowed(about_emoji) {
                        ffi_about_emoji in
                        return try OptionalArgConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.convertArgBorrowed(
                            avatar
                        ) {
                            ffi_avatar in
                            return try OptionalArgConverter<IdentityArgConverter<Bool>, SignalOptionalOfbool>
                                .convertArgBorrowed(phone_number_sharing) {
                                    ffi_phone_number_sharing in
                                    return try OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>
                                        .convertArgBorrowed(payment_address) {
                                            ffi_payment_address in
                                            return try ArrayArgConverter<
                                                StringConverter, SignalBorrowedSliceOfCStringPtr
                                            >.convertArgBorrowed(badge_ids) {
                                                ffi_badge_ids in

                                                return try niceThunk(
                                                    FfiArg(
                                                        given_name: ffi_given_name,
                                                        family_name: ffi_family_name,
                                                        about: ffi_about,
                                                        about_emoji: ffi_about_emoji,
                                                        avatar: ffi_avatar,
                                                        phone_number_sharing: ffi_phone_number_sharing,
                                                        payment_address: ffi_payment_address,
                                                        badge_ids: ffi_badge_ids,
                                                    )
                                                )

                                            }
                                        }
                                }
                        }
                    }
                }
            }
        }

    }
}

internal enum UnauthProfileAuthorizationArgConverterKeepAlive {
    case accessKey((FixedByteArrayConverter<FixedByteArrayHelper16>.KeepAlive?))
    case groupSend((ByteArrayConverter<GroupSendFullToken>.KeepAlive?))
}

internal enum DerivedArgConverterUnauthProfileAuthorization: NiceArgConverter {
    typealias NiceArg = UnauthProfileAuthorization
    typealias FfiArg = SignalUnauthProfileAuthorizationFfiArg
    typealias KeepAlive = UnauthProfileAuthorizationArgConverterKeepAlive
    static func convertArg(_ niceArg: NiceArg) -> (FfiArg, KeepAlive?) {
        switch niceArg {
        case .accessKey(
            let _0,
        ):

            let (_0_ffi, _0_keepalive):
                (
                    FixedByteArrayConverter<FixedByteArrayHelper16>.FfiArg,
                    FixedByteArrayConverter<FixedByteArrayHelper16>.KeepAlive?,
                ) = FixedByteArrayConverter<FixedByteArrayHelper16>.convertArg(_0)

            let ffiStructArg = SignalUnauthProfileAuthorizationFfiArgSignalAccessKey_Body(_0: _0_ffi, )
            let ffiStructKeepAlive: (FixedByteArrayConverter<FixedByteArrayHelper16>.KeepAlive?, )? =
                (_0_keepalive != nil || false)
                ? (_0_keepalive,)
                : nil

            return (
                SignalUnauthProfileAuthorizationFfiArg.init(
                    tag: SignalUnauthProfileAuthorizationFfiArgAccessKey,
                    .init(access_key: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .accessKey($0) },
            )

        case .groupSend(
            let _0,
        ):

            let (_0_ffi, _0_keepalive):
                (
                    ByteArrayConverter<GroupSendFullToken>.FfiArg,
                    ByteArrayConverter<GroupSendFullToken>.KeepAlive?,
                ) = ByteArrayConverter<GroupSendFullToken>.convertArg(_0)

            let ffiStructArg = SignalUnauthProfileAuthorizationFfiArgSignalGroupSend_Body(_0: _0_ffi, )
            let ffiStructKeepAlive: (ByteArrayConverter<GroupSendFullToken>.KeepAlive?, )? =
                (_0_keepalive != nil || false)
                ? (_0_keepalive,)
                : nil

            return (
                SignalUnauthProfileAuthorizationFfiArg.init(
                    tag: SignalUnauthProfileAuthorizationFfiArgGroupSend,
                    .init(group_send: ffiStructArg),
                ),
                ffiStructKeepAlive.map { .groupSend($0) },
            )

        }
    }
    static func convertArgBorrowed<Result>(
        _ niceArg: NiceArg,
        _ niceThunk: (FfiArg) throws -> Result,
    ) rethrows -> Result {
        switch niceArg {

        case .accessKey(
            let _0,
        ):

            return try FixedByteArrayConverter<FixedByteArrayHelper16>.convertArgBorrowed(_0) {
                ffi__0 in

                return try niceThunk(
                    SignalUnauthProfileAuthorizationFfiArg.init(
                        tag: SignalUnauthProfileAuthorizationFfiArgAccessKey,
                        .init(
                            access_key:
                                SignalUnauthProfileAuthorizationFfiArgSignalAccessKey_Body(
                                    _0: ffi__0,
                                )
                        ),
                    )
                )

            }

        case .groupSend(
            let _0,
        ):

            return try ByteArrayConverter<GroupSendFullToken>.convertArgBorrowed(_0) {
                ffi__0 in

                return try niceThunk(
                    SignalUnauthProfileAuthorizationFfiArg.init(
                        tag: SignalUnauthProfileAuthorizationFfiArgGroupSend,
                        .init(
                            group_send:
                                SignalUnauthProfileAuthorizationFfiArgSignalGroupSend_Body(
                                    _0: ffi__0,
                                )
                        ),
                    )
                )

            }

        }
    }
}

internal enum NativeNice {
    internal static func AuthenticatedChatConnection_answer_challenge(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        token: String,
        answer: ChallengeAnswer,
    ) async throws -> Bool {
        let rawOutput: IdentityResultConverter<Bool>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        StringConverter.convertArgBorrowed(token) { tokenFfi in
                            DerivedArgConverterBridgeChallengeAnswer.convertArgBorrowed(answer) { answerFfi in
                                SignalFfi.signal_authenticated_chat_connection_answer_challenge(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    tokenFfi,
                                    answerFfi,
                                )
                            }
                        }
                    }
            }
        return try IdentityResultConverter<Bool>.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_clear_push_token(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_clear_push_token(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_clear_registration_lock(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_clear_registration_lock(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_confirm_totp_key(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        oneTimePassword one_time_password: Int32,
        name: String,
        createdAt created_at: Date,
        svrKey svr_key: Data,
        rng: Int64,
    ) async throws -> Int32 {
        let rawOutput: IdentityResultConverter<Int32>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        IdentityArgConverter<Int32>.convertArgBorrowed(one_time_password) { one_time_passwordFfi in
                            StringConverter.convertArgBorrowed(name) { nameFfi in
                                TimestampConverter.convertArgBorrowed(created_at) { created_atFfi in
                                    FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) {
                                        svr_keyFfi in
                                        IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                            SignalFfi.signal_authenticated_chat_connection_confirm_totp_key(
                                                promiseFfi,
                                                asyncContextFfi.const(),
                                                chatFfi,
                                                one_time_passwordFfi,
                                                nameFfi,
                                                created_atFfi,
                                                svr_keyFfi,
                                                rngFfi,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try IdentityResultConverter<Int32>.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_confirm_username(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        username: String,
        usernameCiphertext username_ciphertext: Data,
        rng: Int64,
    ) async throws -> UUID {
        let rawOutput: UuidNiceConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        StringConverter.convertArgBorrowed(username) { usernameFfi in
                            DataConverter.convertArgBorrowed(username_ciphertext) { username_ciphertextFfi in
                                IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                    SignalFfi.signal_authenticated_chat_connection_confirm_username(
                                        promiseFfi,
                                        asyncContextFfi.const(),
                                        chatFfi,
                                        usernameFfi,
                                        username_ciphertextFfi,
                                        rngFfi,
                                    )
                                }
                            }
                        }
                    }
            }
        return try UuidNiceConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_create_donation_permits(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        requestContext request_context: DonationPermitRequestContext,
        serverParams server_params: ServerPublicParams,
    ) async throws -> [DonationPermit] {
        let rawOutput:
            ArrayReturnConverter<ByteArrayConverter<DonationPermit>, SignalOwnedBufferOfMaxAlignedOwnedBuffer>.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                        .convertArgBorrowed(chat) { chatFfi in
                            ByteArrayConverter<DonationPermitRequestContext>.convertArgBorrowed(request_context) {
                                request_contextFfi in
                                BridgeHandleRefConverter<SignalMutPointerServerPublicParams, ServerPublicParams>
                                    .convertArgBorrowed(server_params) { server_paramsFfi in
                                        SignalFfi.signal_authenticated_chat_connection_create_donation_permits(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            request_contextFfi,
                                            server_paramsFfi,
                                        )
                                    }
                            }
                        }
                }
        return try ArrayReturnConverter<ByteArrayConverter<DonationPermit>, SignalOwnedBufferOfMaxAlignedOwnedBuffer>
            .convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_delete_account(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_delete_account(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_delete_username_hash(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_delete_username_hash(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_delete_username_link(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_delete_username_link(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_finish_mfa_verification(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        credential: BridgeMfaVerificationCredential,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        DerivedArgConverterBridgeMfaVerificationCredential.convertArgBorrowed(credential) {
                            credentialFfi in
                            SignalFfi.signal_authenticated_chat_connection_finish_mfa_verification(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                credentialFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_finish_web_authn_registration(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        attestationObject attestation_object: Data,
        collectedClientDataJson collected_client_data_json: String,
        name: String,
        createdAt created_at: Date,
        svrKey svr_key: Data,
        rng: Int64,
    ) async throws -> Int32 {
        let rawOutput: IdentityResultConverter<Int32>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        DataConverter.convertArgBorrowed(attestation_object) { attestation_objectFfi in
                            StringConverter.convertArgBorrowed(collected_client_data_json) {
                                collected_client_data_jsonFfi in
                                StringConverter.convertArgBorrowed(name) { nameFfi in
                                    TimestampConverter.convertArgBorrowed(created_at) { created_atFfi in
                                        FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) {
                                            svr_keyFfi in
                                            IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                                SignalFfi
                                                    .signal_authenticated_chat_connection_finish_web_authn_registration(
                                                        promiseFfi,
                                                        asyncContextFfi.const(),
                                                        chatFfi,
                                                        attestation_objectFfi,
                                                        collected_client_data_jsonFfi,
                                                        nameFfi,
                                                        created_atFfi,
                                                        svr_keyFfi,
                                                        rngFfi,
                                                    )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try IdentityResultConverter<Int32>.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_generate_totp_key(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> BridgePendingTotpKey {
        let rawOutput: DerivedReturnConverterBridgePendingTotpKey.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_generate_totp_key(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try DerivedReturnConverterBridgePendingTotpKey.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_account_identity(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> BridgeAccountIdentity {
        let rawOutput: DerivedReturnConverterBridgeAccountIdentity.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_get_account_identity(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try DerivedReturnConverterBridgeAccountIdentity.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_avatar_credential(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        aci: Aci,
        keyPair key_pair: ZkCredentialKeyPair,
        rotationId rotation_id: Int64,
        serverPublicParams server_public_params: GenericServerPublicParams,
        currentTimeSeconds current_time_seconds: Int64,
        rng: Int64,
    ) async throws -> AvatarUploadCredential {
        let rawOutput: ByteArrayConverter<AvatarUploadCredential>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        AciConverter.convertArgBorrowed(aci) { aciFfi in
                            ByteArrayConverter<ZkCredentialKeyPair>.convertArgBorrowed(key_pair) { key_pairFfi in
                                IdentityArgConverter<Int64>.convertArgBorrowed(rotation_id) { rotation_idFfi in
                                    ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(
                                        server_public_params
                                    ) { server_public_paramsFfi in
                                        IdentityArgConverter<Int64>.convertArgBorrowed(current_time_seconds) {
                                            current_time_secondsFfi in
                                            IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                                SignalFfi.signal_authenticated_chat_connection_get_avatar_credential(
                                                    promiseFfi,
                                                    asyncContextFfi.const(),
                                                    chatFfi,
                                                    aciFfi,
                                                    key_pairFfi,
                                                    rotation_idFfi,
                                                    server_public_paramsFfi,
                                                    current_time_secondsFfi,
                                                    rngFfi,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try ByteArrayConverter<AvatarUploadCredential>.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_avatar_upload_form_legacy(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        aci: Aci,
        profileKey profile_key: ProfileKey,
    ) async throws -> S3UploadForm {
        let rawOutput: DerivedReturnConverterS3UploadFormInternal.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        AciConverter.convertArgBorrowed(aci) { aciFfi in
                            ByteArrayConverter<ProfileKey>.convertArgBorrowed(profile_key) { profile_keyFfi in
                                SignalFfi.signal_authenticated_chat_connection_get_avatar_upload_form_legacy(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    aciFfi,
                                    profile_keyFfi,
                                )
                            }
                        }
                    }
            }
        return try DerivedReturnConverterS3UploadFormInternal.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_badges(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        etag: Data?,
    ) async throws -> TaggedBadges? {
        let rawOutput:
            OptionalReturnConverter<DerivedReturnConverterTaggedBadges, SignalOptionalOfTaggedBadgesFfiResult>.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                        .convertArgBorrowed(chat) { chatFfi in
                            OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.convertArgBorrowed(etag)
                            { etagFfi in
                                SignalFfi.signal_authenticated_chat_connection_get_badges(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    etagFfi,
                                )
                            }
                        }
                }
        return try OptionalReturnConverter<DerivedReturnConverterTaggedBadges, SignalOptionalOfTaggedBadgesFfiResult>
            .convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_capabilities(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> [DeviceCapability] {
        let rawOutput:
            ArrayReturnConverter<
                DerivedReturnConverterDeviceCapabilityInternal,
                SignalOwnedBufferOfMaxAlignedDeviceCapabilityInternalFfiResult
            >.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                        .convertArgBorrowed(chat) { chatFfi in
                            SignalFfi.signal_authenticated_chat_connection_get_capabilities(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                            )
                        }
                }
        return try ArrayReturnConverter<
            DerivedReturnConverterDeviceCapabilityInternal,
            SignalOwnedBufferOfMaxAlignedDeviceCapabilityInternalFfiResult
        >.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_currency_conversions(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> CurrencyConversionsInternal {
        let rawOutput: DerivedReturnConverterCurrencyConversionsInternal.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_get_currency_conversions(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try DerivedReturnConverterCurrencyConversionsInternal.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_devices(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> [LinkedDevice] {
        let rawOutput:
            ArrayReturnConverter<
                DerivedReturnConverterLinkedDeviceInternal, SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult
            >.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                        .convertArgBorrowed(chat) { chatFfi in
                            SignalFfi.signal_authenticated_chat_connection_get_devices(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                            )
                        }
                }
        return try ArrayReturnConverter<
            DerivedReturnConverterLinkedDeviceInternal, SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult
        >.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_entitlements(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> AccountEntitlements {
        let rawOutput: DerivedReturnConverterAccountEntitlements.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_get_entitlements(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try DerivedReturnConverterAccountEntitlements.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_pre_key_count(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> BridgePreKeyCounts {
        let rawOutput: DerivedReturnConverterBridgePreKeyCounts.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_get_pre_key_count(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try DerivedReturnConverterBridgePreKeyCounts.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_profile(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        aci: Aci,
        profileKey profile_key: ProfileKey,
        etag: Data?,
    ) async throws -> FetchedProfile? {
        let rawOutput:
            OptionalReturnConverter<DerivedReturnConverterFetchedProfile, SignalOptionalOfFetchedProfileFfiResult>
                .FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                        .convertArgBorrowed(chat) { chatFfi in
                            AciConverter.convertArgBorrowed(aci) { aciFfi in
                                ByteArrayConverter<ProfileKey>.convertArgBorrowed(profile_key) { profile_keyFfi in
                                    OptionalFixedByteArrayConverter<FixedByteArrayHelper10>.convertArgBorrowed(etag) {
                                        etagFfi in
                                        SignalFfi.signal_authenticated_chat_connection_get_profile(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            aciFfi,
                                            profile_keyFfi,
                                            etagFfi,
                                        )
                                    }
                                }
                            }
                        }
                }
        return try OptionalReturnConverter<
            DerivedReturnConverterFetchedProfile, SignalOptionalOfFetchedProfileFfiResult
        >.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_get_sticker_upload_forms(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        numberOfStickers number_of_stickers: Int32,
    ) async throws -> GetStickerUploadFormsResponse {
        let rawOutput: DerivedReturnConverterGetStickerUploadFormsResponse.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        IdentityArgConverter<Int32>.convertArgBorrowed(number_of_stickers) { number_of_stickersFfi in
                            SignalFfi.signal_authenticated_chat_connection_get_sticker_upload_forms(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                number_of_stickersFfi,
                            )
                        }
                    }
            }
        return try DerivedReturnConverterGetStickerUploadFormsResponse.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_list_mfa_keys(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        svrKey svr_key: Data,
    ) async throws -> [BridgeConfirmedMfaKey] {
        let rawOutput:
            ArrayReturnConverter<
                DerivedReturnConverterBridgeConfirmedMfaKey, SignalOwnedBufferOfMaxAlignedBridgeConfirmedMfaKeyFfiResult
            >.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                        .convertArgBorrowed(chat) { chatFfi in
                            FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) { svr_keyFfi in
                                SignalFfi.signal_authenticated_chat_connection_list_mfa_keys(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    svr_keyFfi,
                                )
                            }
                        }
                }
        return try ArrayReturnConverter<
            DerivedReturnConverterBridgeConfirmedMfaKey, SignalOwnedBufferOfMaxAlignedBridgeConfirmedMfaKeyFfiResult
        >.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_redeem_backup_receipt(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        presentation: ReceiptCredentialPresentation,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        FixedLengthSerializedConverter<ReceiptCredentialPresentation, FixedByteArrayHelper329>
                            .convertArgBorrowed(presentation) { presentationFfi in
                                SignalFfi.signal_authenticated_chat_connection_redeem_backup_receipt(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    presentationFfi,
                                )
                            }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_redeem_donation_receipt(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        presentation: ReceiptCredentialPresentation,
        visibility: BadgeVisibility,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        FixedLengthSerializedConverter<ReceiptCredentialPresentation, FixedByteArrayHelper329>
                            .convertArgBorrowed(presentation) { presentationFfi in
                                DerivedArgConverterBadgeVisibility.convertArgBorrowed(visibility) { visibilityFfi in
                                    SignalFfi.signal_authenticated_chat_connection_redeem_donation_receipt(
                                        promiseFfi,
                                        asyncContextFfi.const(),
                                        chatFfi,
                                        presentationFfi,
                                        visibilityFfi,
                                    )
                                }
                            }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_remove_device(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        deviceId device_id: DeviceId,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        DeviceIdConverter.convertArgBorrowed(device_id) { device_idFfi in
                            SignalFfi.signal_authenticated_chat_connection_remove_device(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                device_idFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_remove_mfa_key(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        keyId key_id: Int32,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        IdentityArgConverter<Int32>.convertArgBorrowed(key_id) { key_idFfi in
                            SignalFfi.signal_authenticated_chat_connection_remove_mfa_key(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                key_idFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_report_message(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        source: Aci,
        messageGuid message_guid: UUID,
        reportSpamToken report_spam_token: Data,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        AciConverter.convertArgBorrowed(source) { sourceFfi in
                            UuidNiceConverter.convertArgBorrowed(message_guid) { message_guidFfi in
                                DataConverter.convertArgBorrowed(report_spam_token) { report_spam_tokenFfi in
                                    SignalFfi.signal_authenticated_chat_connection_report_message(
                                        promiseFfi,
                                        asyncContextFfi.const(),
                                        chatFfi,
                                        sourceFfi,
                                        message_guidFfi,
                                        report_spam_tokenFfi,
                                    )
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_reserve_username_hash(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        usernameHashes username_hashes: [Data],
    ) async throws -> Data {
        let rawOutput: FixedByteArrayConverter<FixedByteArrayHelper32>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ArrayArgConverter<
                            FixedByteArrayConverter<FixedByteArrayHelper32>, SignalBorrowedSliceOfPtrToc_uchar32
                        >.convertArgBorrowed(username_hashes) { username_hashesFfi in
                            SignalFfi.signal_authenticated_chat_connection_reserve_username_hash(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                username_hashesFfi,
                            )
                        }
                    }
            }
        return try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_capabilities(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        capabilities: [DeviceCapability],
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ArrayArgConverter<
                            DerivedArgConverterDeviceCapabilityInternal,
                            SignalBorrowedSliceOfDeviceCapabilityInternalFfiArg
                        >.convertArgBorrowed(capabilities) { capabilitiesFfi in
                            SignalFfi.signal_authenticated_chat_connection_set_capabilities(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                capabilitiesFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_device_name(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        deviceId device_id: DeviceId,
        encryptedName encrypted_name: Data,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        DeviceIdConverter.convertArgBorrowed(device_id) { device_idFfi in
                            DataConverter.convertArgBorrowed(encrypted_name) { encrypted_nameFfi in
                                SignalFfi.signal_authenticated_chat_connection_set_device_name(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    device_idFfi,
                                    encrypted_nameFfi,
                                )
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_discoverable_by_phone_number(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        discoverable: Bool,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        IdentityArgConverter<Bool>.convertArgBorrowed(discoverable) { discoverableFfi in
                            SignalFfi.signal_authenticated_chat_connection_set_discoverable_by_phone_number(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                discoverableFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_last_resort_kem_pre_key(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        identityType identity_type: ServiceIdKind,
        id: UInt32,
        key: KEMPublicKey,
        signature: Data,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ServiceIdKindConverter.convertArgBorrowed(identity_type) { identity_typeFfi in
                            IdentityArgConverter<UInt32>.convertArgBorrowed(id) { idFfi in
                                BridgeHandleRefConverter<SignalMutPointerKyberPublicKey, KEMPublicKey>
                                    .convertArgBorrowed(key) { keyFfi in
                                        DataConverter.convertArgBorrowed(signature) { signatureFfi in
                                            SignalFfi.signal_authenticated_chat_connection_set_last_resort_kem_pre_key(
                                                promiseFfi,
                                                asyncContextFfi.const(),
                                                chatFfi,
                                                identity_typeFfi,
                                                idFfi,
                                                keyFfi,
                                                signatureFfi,
                                            )
                                        }
                                    }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_mfa_key_metadata(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        keyId key_id: Int32,
        name: String,
        createdAt created_at: Date,
        svrKey svr_key: Data,
        rng: Int64,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        IdentityArgConverter<Int32>.convertArgBorrowed(key_id) { key_idFfi in
                            StringConverter.convertArgBorrowed(name) { nameFfi in
                                TimestampConverter.convertArgBorrowed(created_at) { created_atFfi in
                                    FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) {
                                        svr_keyFfi in
                                        IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                            SignalFfi.signal_authenticated_chat_connection_set_mfa_key_metadata(
                                                promiseFfi,
                                                asyncContextFfi.const(),
                                                chatFfi,
                                                key_idFfi,
                                                nameFfi,
                                                created_atFfi,
                                                svr_keyFfi,
                                                rngFfi,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_one_time_ec_pre_keys(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        identityType identity_type: ServiceIdKind,
        preKeyIds pre_key_ids: [UInt32],
        preKeyData pre_key_data: [PublicKey],
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ServiceIdKindConverter.convertArgBorrowed(identity_type) { identity_typeFfi in
                            ArrayArgConverter<IdentityArgConverter, SignalBorrowedSliceOfu32>.convertArgBorrowed(
                                pre_key_ids
                            ) { pre_key_idsFfi in
                                ArrayArgConverter<
                                    BridgeHandleRefConverter<SignalMutPointerPublicKey, PublicKey>,
                                    SignalBorrowedSliceOfConstPointerPublicKey
                                >.convertArgBorrowed(pre_key_data) { pre_key_dataFfi in
                                    SignalFfi.signal_authenticated_chat_connection_set_one_time_ec_pre_keys(
                                        promiseFfi,
                                        asyncContextFfi.const(),
                                        chatFfi,
                                        identity_typeFfi,
                                        pre_key_idsFfi,
                                        pre_key_dataFfi,
                                    )
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_one_time_kem_pre_keys(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        identityType identity_type: ServiceIdKind,
        preKeyIds pre_key_ids: [UInt32],
        preKeyData pre_key_data: [KEMPublicKey],
        preKeySignatures pre_key_signatures: [Data],
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ServiceIdKindConverter.convertArgBorrowed(identity_type) { identity_typeFfi in
                            ArrayArgConverter<IdentityArgConverter, SignalBorrowedSliceOfu32>.convertArgBorrowed(
                                pre_key_ids
                            ) { pre_key_idsFfi in
                                ArrayArgConverter<
                                    BridgeHandleRefConverter<SignalMutPointerKyberPublicKey, KEMPublicKey>,
                                    SignalBorrowedSliceOfConstPointerKyberPublicKey
                                >.convertArgBorrowed(pre_key_data) { pre_key_dataFfi in
                                    ArrayArgConverter<DataConverter, SignalBorrowedSliceOfBuffers>.convertArgBorrowed(
                                        pre_key_signatures
                                    ) { pre_key_signaturesFfi in
                                        SignalFfi.signal_authenticated_chat_connection_set_one_time_kem_pre_keys(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            identity_typeFfi,
                                            pre_key_idsFfi,
                                            pre_key_dataFfi,
                                            pre_key_signaturesFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_profile(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        rng: Int64,
        aci: Aci,
        profileKey profile_key: ProfileKey,
        profile: Profile,
        expectedCurrentDataHash expected_current_data_hash: Data?,
        expectedCurrentProfileKeyVersion expected_current_profile_key_version: ProfileKeyVersion?,
    ) async throws -> Data {
        let rawOutput: FixedByteArrayConverter<FixedByteArrayHelper32>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                            AciConverter.convertArgBorrowed(aci) { aciFfi in
                                ByteArrayConverter<ProfileKey>.convertArgBorrowed(profile_key) { profile_keyFfi in
                                    DerivedArgConverterProfile.convertArgBorrowed(profile) { profileFfi in
                                        OptionalFixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(
                                            expected_current_data_hash
                                        ) { expected_current_data_hashFfi in
                                            OptionalArgConverter<
                                                ProfileKeyVersionArgConverter<
                                                    FixedByteArrayConverter<FixedByteArrayHelper64>
                                                >, SignalOptionalOfPtrToc_uchar64
                                            >.convertArgBorrowed(expected_current_profile_key_version) {
                                                expected_current_profile_key_versionFfi in
                                                SignalFfi.signal_authenticated_chat_connection_set_profile(
                                                    promiseFfi,
                                                    asyncContextFfi.const(),
                                                    chatFfi,
                                                    rngFfi,
                                                    aciFfi,
                                                    profile_keyFfi,
                                                    profileFfi,
                                                    expected_current_data_hashFfi,
                                                    expected_current_profile_key_versionFfi,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_push_token_apns(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        apnsToken apns_token: String,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        StringConverter.convertArgBorrowed(apns_token) { apns_tokenFfi in
                            SignalFfi.signal_authenticated_chat_connection_set_push_token_apns(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                apns_tokenFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_registration_lock(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        svrKey svr_key: Data,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) { svr_keyFfi in
                            SignalFfi.signal_authenticated_chat_connection_set_registration_lock(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                svr_keyFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_registration_recovery_password(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        svrKey svr_key: Data,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) { svr_keyFfi in
                            SignalFfi.signal_authenticated_chat_connection_set_registration_recovery_password(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                svr_keyFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_signed_ec_pre_key(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        identityType identity_type: ServiceIdKind,
        id: UInt32,
        key: PublicKey,
        signature: Data,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ServiceIdKindConverter.convertArgBorrowed(identity_type) { identity_typeFfi in
                            IdentityArgConverter<UInt32>.convertArgBorrowed(id) { idFfi in
                                BridgeHandleRefConverter<SignalMutPointerPublicKey, PublicKey>.convertArgBorrowed(key) {
                                    keyFfi in
                                    DataConverter.convertArgBorrowed(signature) { signatureFfi in
                                        SignalFfi.signal_authenticated_chat_connection_set_signed_ec_pre_key(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            identity_typeFfi,
                                            idFfi,
                                            keyFfi,
                                            signatureFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_username_link(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        usernameCiphertext username_ciphertext: Data,
        keepLinkHandle keep_link_handle: Bool,
    ) async throws -> UUID {
        let rawOutput: UuidNiceConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        DataConverter.convertArgBorrowed(username_ciphertext) { username_ciphertextFfi in
                            IdentityArgConverter<Bool>.convertArgBorrowed(keep_link_handle) { keep_link_handleFfi in
                                SignalFfi.signal_authenticated_chat_connection_set_username_link(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    username_ciphertextFfi,
                                    keep_link_handleFfi,
                                )
                            }
                        }
                    }
            }
        return try UuidNiceConverter.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_set_zk_credential_key(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
        rng: Int64,
    ) async throws -> (ZkCredentialKeyPair, Int64) {
        let rawOutput:
            PairOfResultConverter<
                ByteArrayConverter<ZkCredentialKeyPair>, IdentityResultConverter<Int64>, SignalPairOfOwnedBufferi64
            >.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                        .convertArgBorrowed(chat) { chatFfi in
                            IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                SignalFfi.signal_authenticated_chat_connection_set_zk_credential_key(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    rngFfi,
                                )
                            }
                        }
                }
        return try PairOfResultConverter<
            ByteArrayConverter<ZkCredentialKeyPair>, IdentityResultConverter<Int64>, SignalPairOfOwnedBufferi64
        >.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_start_mfa_verification(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> StartMfaVerificationResponse {
        let rawOutput: DerivedReturnConverterStartMfaVerificationResponse.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_start_mfa_verification(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try DerivedReturnConverterStartMfaVerificationResponse.convertReturn(consuming: rawOutput)

    }
    internal static func AuthenticatedChatConnection_start_web_authn_registration(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> BridgeWebAuthnCreateParameters {
        let rawOutput: DerivedReturnConverterBridgeWebAuthnCreateParameters.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerAuthenticatedChatConnection, AuthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        SignalFfi.signal_authenticated_chat_connection_start_web_authn_registration(
                            promiseFfi,
                            asyncContextFfi.const(),
                            chatFfi,
                        )
                    }
            }
        return try DerivedReturnConverterBridgeWebAuthnCreateParameters.convertReturn(consuming: rawOutput)

    }
    internal static func BackupJsonExporter_ExportFrames(
        exporter: BackupJsonExporter,
        frames: Data,
    ) throws -> [(String?, String?)] {
        try BridgeHandleMutRefConverter<SignalMutPointerBackupJsonExporter, BackupJsonExporter>.convertArgBorrowed(
            exporter
        ) { exporterFfi in
            try DataConverter.convertArgBorrowed(frames) { framesFfi in
                var rawOutput = ArrayReturnConverter<
                    PairOfResultConverter<
                        OptionalStringConverter, OptionalStringConverter, SignalPairOfCStringPtrCStringPtr
                    >, SignalOwnedBufferOfMaxAlignedPairOfCStringPtrCStringPtr
                >.emptyFfiReturn()
                try checkError(
                    SignalFfi.signal_backup_json_exporter_export_frames(
                        &rawOutput,
                        exporterFfi,
                        framesFfi,
                    )
                )
                return try ArrayReturnConverter<
                    PairOfResultConverter<
                        OptionalStringConverter, OptionalStringConverter, SignalPairOfCStringPtrCStringPtr
                    >, SignalOwnedBufferOfMaxAlignedPairOfCStringPtrCStringPtr
                >.convertReturn(consuming: rawOutput)
            }
        }

    }
    internal static func BackupJsonExporter_Finish(
        exporter: BackupJsonExporter,
    ) throws {
        try BridgeHandleMutRefConverter<SignalMutPointerBackupJsonExporter, BackupJsonExporter>.convertArgBorrowed(
            exporter
        ) { exporterFfi in
            try checkError(
                SignalFfi.signal_backup_json_exporter_finish(
                    exporterFfi,
                )
            )
        }

    }
    internal static func BackupJsonExporter_GetInitialChunk(
        exporter: BackupJsonExporter,
    ) throws -> String {
        try BridgeHandleRefConverter<SignalMutPointerBackupJsonExporter, BackupJsonExporter>.convertArgBorrowed(
            exporter
        ) { exporterFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_backup_json_exporter_get_initial_chunk(
                    &rawOutput,
                    exporterFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func CdnUrl_validate(
        url: String,
    ) throws -> Bool {
        try StringConverter.convertArgBorrowed(url) { urlFfi in
            var rawOutput = IdentityResultConverter<Bool>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_cdn_url_validate(
                    &rawOutput,
                    urlFfi,
                )
            )
            return try IdentityResultConverter<Bool>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func CopyBackupMediaStream_next(
        asyncContext: TokioAsyncContext,
        stream: CopyBackupMediaStream,
    ) async throws -> CopyBackupMediaNextChunk {
        let rawOutput: DerivedReturnConverterCopyBackupMediaNextChunk.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerCopyBackupMediaStream, CopyBackupMediaStream>
                    .convertArgBorrowed(stream) { streamFfi in
                        SignalFfi.signal_copy_backup_media_stream_next(
                            promiseFfi,
                            asyncContextFfi.const(),
                            streamFfi,
                        )
                    }
            }
        return try DerivedReturnConverterCopyBackupMediaNextChunk.convertReturn(consuming: rawOutput)

    }
    internal static func DeleteBackupMediaStream_next(
        asyncContext: TokioAsyncContext,
        stream: DeleteBackupMediaStream,
    ) async throws -> DeleteBackupMediaNextChunk {
        let rawOutput: DerivedReturnConverterDeleteBackupMediaNextChunk.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerDeleteBackupMediaStream, DeleteBackupMediaStream>
                    .convertArgBorrowed(stream) { streamFfi in
                        SignalFfi.signal_delete_backup_media_stream_next(
                            promiseFfi,
                            asyncContextFfi.const(),
                            streamFfi,
                        )
                    }
            }
        return try DerivedReturnConverterDeleteBackupMediaNextChunk.convertReturn(consuming: rawOutput)

    }
    internal static func Error_GetChargeFailure(
        err: SignalFfiErrorRef?,
    ) throws -> ChargeFailure? {
        try IdentityArgConverter<SignalFfiErrorRef?>.convertArgBorrowed(err) { errFfi in
            var rawOutput = OptionalReturnConverter<
                DerivedReturnConverterChargeFailure, SignalOptionalOfChargeFailureFfiResult
            >.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_error_get_charge_failure(
                    &rawOutput,
                    errFfi,
                )
            )
            return try OptionalReturnConverter<
                DerivedReturnConverterChargeFailure, SignalOptionalOfChargeFailureFfiResult
            >.convertReturn(consuming: rawOutput)
        }

    }
    internal static func Error_GetCurrentProfileVersion(
        err: SignalFfiErrorRef?,
    ) throws -> ProfileKeyVersion? {
        try IdentityArgConverter<SignalFfiErrorRef?>.convertArgBorrowed(err) { errFfi in
            var rawOutput = OptionalReturnConverter<
                ProfileKeyVersionReturnConverter<FixedByteArrayConverter<FixedByteArrayHelper64>>,
                SignalOptionalOfc_uchar64
            >.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_error_get_current_profile_version(
                    &rawOutput,
                    errFfi,
                )
            )
            return try OptionalReturnConverter<
                ProfileKeyVersionReturnConverter<FixedByteArrayConverter<FixedByteArrayHelper64>>,
                SignalOptionalOfc_uchar64
            >.convertReturn(consuming: rawOutput)
        }

    }
    internal static func Error_GetProfileValidationError(
        err: SignalFfiErrorRef?,
    ) throws -> ProfileValidationErrorInternal {
        try IdentityArgConverter<SignalFfiErrorRef?>.convertArgBorrowed(err) { errFfi in
            var rawOutput = DerivedReturnConverterProfileValidationErrorInternal.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_error_get_profile_validation_error(
                    &rawOutput,
                    errFfi,
                )
            )
            return try DerivedReturnConverterProfileValidationErrorInternal.convertReturn(consuming: rawOutput)
        }

    }
    internal static func ProvisioningPublicKey_Serialize(
        key: ProvisioningPublicKey,
    ) throws -> Data {
        try BridgeHandleRefConverter<SignalMutPointerProvisioningPublicKey, ProvisioningPublicKey>.convertArgBorrowed(
            key
        ) { keyFfi in
            var rawOutput = DataConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_provisioning_public_key_serialize(
                    &rawOutput,
                    keyFfi,
                )
            )
            return try DataConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func Provisioning_EncryptProvisionMessage(
        secondaryPublicKey secondary_public_key: ProvisioningPublicKey,
        provisionMessage provision_message: Data,
    ) throws -> Data {
        try BridgeHandleRefConverter<SignalMutPointerProvisioningPublicKey, ProvisioningPublicKey>.convertArgBorrowed(
            secondary_public_key
        ) { secondary_public_keyFfi in
            try DataConverter.convertArgBorrowed(provision_message) { provision_messageFfi in
                var rawOutput = DataConverter.emptyFfiReturn()
                try checkError(
                    SignalFfi.signal_provisioning_encrypt_provision_message(
                        &rawOutput,
                        secondary_public_keyFfi,
                        provision_messageFfi,
                    )
                )
                return try DataConverter.convertReturn(consuming: rawOutput)
            }
        }

    }
    internal static func RecvProvisionCiphertextState_DecryptEnvelope(
        state: RecvProvisionCiphertextState,
        envelope: Data,
    ) throws -> Data {
        try BridgeHandleRefConverter<SignalMutPointerRecvProvisionCiphertextState, RecvProvisionCiphertextState>
            .convertArgBorrowed(state) { stateFfi in
                try DataConverter.convertArgBorrowed(envelope) { envelopeFfi in
                    var rawOutput = DataConverter.emptyFfiReturn()
                    try checkError(
                        SignalFfi.signal_recv_provision_ciphertext_state_decrypt_envelope(
                            &rawOutput,
                            stateFfi,
                            envelopeFfi,
                        )
                    )
                    return try DataConverter.convertReturn(consuming: rawOutput)
                }
            }

    }
    internal static func RecvProvisionCiphertextState_Generate() throws -> RecvProvisionCiphertextState {
        var rawOutput = BridgeHandleConverter<
            SignalMutPointerRecvProvisionCiphertextState, RecvProvisionCiphertextState
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_recv_provision_ciphertext_state_generate(
                &rawOutput,
            )
        )
        return try BridgeHandleConverter<SignalMutPointerRecvProvisionCiphertextState, RecvProvisionCiphertextState>
            .convertReturn(consuming: rawOutput)

    }
    internal static func RecvProvisionCiphertextState_GetPublicKey(
        state: RecvProvisionCiphertextState,
    ) throws -> ProvisioningPublicKey {
        try BridgeHandleRefConverter<SignalMutPointerRecvProvisionCiphertextState, RecvProvisionCiphertextState>
            .convertArgBorrowed(state) { stateFfi in
                var rawOutput = BridgeHandleConverter<SignalMutPointerProvisioningPublicKey, ProvisioningPublicKey>
                    .emptyFfiReturn()
                try checkError(
                    SignalFfi.signal_recv_provision_ciphertext_state_get_public_key(
                        &rawOutput,
                        stateFfi,
                    )
                )
                return try BridgeHandleConverter<SignalMutPointerProvisioningPublicKey, ProvisioningPublicKey>
                    .convertReturn(consuming: rawOutput)
            }

    }
    internal static func SvrKey_DeriveLoggingKey(
        svrKey svr_key: Data,
    ) throws -> Data {
        try FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) { svr_keyFfi in
            var rawOutput = FixedByteArrayConverter<FixedByteArrayHelper32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_svr_key_derive_logging_key(
                    &rawOutput,
                    svr_keyFfi,
                )
            )
            return try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func SvrKey_DeriveRegistrationLock(
        svrKey svr_key: Data,
    ) throws -> Data {
        try FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) { svr_keyFfi in
            var rawOutput = FixedByteArrayConverter<FixedByteArrayHelper32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_svr_key_derive_registration_lock(
                    &rawOutput,
                    svr_keyFfi,
                )
            )
            return try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func SvrKey_DeriveRegistrationRecoveryPassword(
        svrKey svr_key: Data,
    ) throws -> Data {
        try FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) { svr_keyFfi in
            var rawOutput = FixedByteArrayConverter<FixedByteArrayHelper32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_svr_key_derive_registration_recovery_password(
                    &rawOutput,
                    svr_keyFfi,
                )
            )
            return try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func SvrKey_DeriveStorageServiceKey(
        svrKey svr_key: Data,
    ) throws -> Data {
        try FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(svr_key) { svr_keyFfi in
            var rawOutput = FixedByteArrayConverter<FixedByteArrayHelper32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_svr_key_derive_storage_service_key(
                    &rawOutput,
                    svr_keyFfi,
                )
            )
            return try FixedByteArrayConverter<FixedByteArrayHelper32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func UnauthenticatedChatConnection_account_exists(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        account: ServiceId,
    ) async throws -> Bool {
        let rawOutput: IdentityResultConverter<Bool>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ServiceIdConverter.convertArgBorrowed(account) { accountFfi in
                            SignalFfi.signal_unauthenticated_chat_connection_account_exists(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                accountFfi,
                            )
                        }
                    }
            }
        return try IdentityResultConverter<Bool>.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_copy_media(
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        items: [BridgeCopyBackupMediaItem],
        rng: Int64,
    ) throws -> CopyBackupMediaStream {
        try BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
            .convertArgBorrowed(chat) { chatFfi in
                try ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                    try ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                        server_keysFfi in
                        try BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                            signing_key
                        ) { signing_keyFfi in
                            try ArrayArgConverter<
                                DerivedArgConverterBridgeCopyBackupMediaItem,
                                SignalBorrowedSliceOfBridgeCopyBackupMediaItemFfiArg
                            >.convertArgBorrowed(items) { itemsFfi in
                                try IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                    var rawOutput = BridgeHandleConverter<
                                        SignalMutPointerCopyBackupMediaStream, CopyBackupMediaStream
                                    >.emptyFfiReturn()
                                    try checkError(
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_copy_media(
                                            &rawOutput,
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            itemsFfi,
                                            rngFfi,
                                        )
                                    )
                                    return try BridgeHandleConverter<
                                        SignalMutPointerCopyBackupMediaStream, CopyBackupMediaStream
                                    >.convertReturn(consuming: rawOutput)
                                }
                            }
                        }
                    }
                }
            }

    }
    internal static func UnauthenticatedChatConnection_backup_delete_all(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_delete_all(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_delete_media(
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        items: [BridgeDeleteBackupMediaItem],
        rng: Int64,
    ) throws -> DeleteBackupMediaStream {
        try BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
            .convertArgBorrowed(chat) { chatFfi in
                try ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                    try ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                        server_keysFfi in
                        try BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                            signing_key
                        ) { signing_keyFfi in
                            try ArrayArgConverter<
                                DerivedArgConverterBridgeDeleteBackupMediaItem,
                                SignalBorrowedSliceOfBridgeDeleteBackupMediaItemFfiArg
                            >.convertArgBorrowed(items) { itemsFfi in
                                try IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                    var rawOutput = BridgeHandleConverter<
                                        SignalMutPointerDeleteBackupMediaStream, DeleteBackupMediaStream
                                    >.emptyFfiReturn()
                                    try checkError(
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_delete_media(
                                            &rawOutput,
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            itemsFfi,
                                            rngFfi,
                                        )
                                    )
                                    return try BridgeHandleConverter<
                                        SignalMutPointerDeleteBackupMediaStream, DeleteBackupMediaStream
                                    >.convertReturn(consuming: rawOutput)
                                }
                            }
                        }
                    }
                }
            }

    }
    internal static func UnauthenticatedChatConnection_backup_get_cdn_credentials(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        cdn: Int32,
        rng: Int64,
    ) async throws -> BackupCdnCredentials {
        let rawOutput: BackupCdnCredentialsConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityArgConverter<Int32>.convertArgBorrowed(cdn) { cdnFfi in
                                        IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                            SignalFfi.signal_unauthenticated_chat_connection_backup_get_cdn_credentials(
                                                promiseFfi,
                                                asyncContextFfi.const(),
                                                chatFfi,
                                                credentialFfi,
                                                server_keysFfi,
                                                signing_keyFfi,
                                                cdnFfi,
                                                rngFfi,
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try BackupCdnCredentialsConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_get_media_backup_info(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws -> BridgeMediaBackupInfo {
        let rawOutput: DerivedReturnConverterBridgeMediaBackupInfo.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_get_media_backup_info(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try DerivedReturnConverterBridgeMediaBackupInfo.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_get_message_backup_info(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws -> BridgeMessageBackupInfo {
        let rawOutput: DerivedReturnConverterBridgeMessageBackupInfo.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_get_message_backup_info(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try DerivedReturnConverterBridgeMessageBackupInfo.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_get_svrb_credentials(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws -> (String, String) {
        let rawOutput:
            PairOfResultConverter<StringConverter, StringConverter, SignalPairOfCStringPtrCStringPtr>.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<
                        SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection
                    >.convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_get_svrb_credentials(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
        return try PairOfResultConverter<StringConverter, StringConverter, SignalPairOfCStringPtrCStringPtr>
            .convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_list_media(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        cursor: String,
        limit: Int32,
        rng: Int64,
    ) async throws -> ListMediaResponse {
        let rawOutput: DerivedReturnConverterListMediaResponse.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    StringConverter.convertArgBorrowed(cursor) { cursorFfi in
                                        IdentityArgConverter<Int32>.convertArgBorrowed(limit) { limitFfi in
                                            IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                                SignalFfi.signal_unauthenticated_chat_connection_backup_list_media(
                                                    promiseFfi,
                                                    asyncContextFfi.const(),
                                                    chatFfi,
                                                    credentialFfi,
                                                    server_keysFfi,
                                                    signing_keyFfi,
                                                    cursorFfi,
                                                    limitFfi,
                                                    rngFfi,
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
            }
        return try DerivedReturnConverterListMediaResponse.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_refresh(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_refresh(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_backup_set_public_key(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: BackupAuthCredential,
        serverKeys server_keys: GenericServerPublicParams,
        signingKey signing_key: PrivateKey,
        rng: Int64,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<BackupAuthCredential>.convertArgBorrowed(credential) { credentialFfi in
                            ByteArrayConverter<GenericServerPublicParams>.convertArgBorrowed(server_keys) {
                                server_keysFfi in
                                BridgeHandleRefConverter<SignalMutPointerPrivateKey, PrivateKey>.convertArgBorrowed(
                                    signing_key
                                ) { signing_keyFfi in
                                    IdentityArgConverter.convertArgBorrowed(rng) { rngFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_backup_set_public_key(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            credentialFfi,
                                            server_keysFfi,
                                            signing_keyFfi,
                                            rngFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_check_svr_credentials(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        number: String,
        credentials: [String],
    ) async throws -> [(String, AuthCheckResult)] {
        let rawOutput:
            ArrayReturnConverter<
                PairOfResultConverter<
                    StringConverter, DerivedReturnConverterAuthCheckResult,
                    SignalPairOfCStringPtrAuthCheckResultFfiResult
                >, SignalOwnedBufferOfMaxAlignedPairOfCStringPtrAuthCheckResultFfiResult
            >.FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<
                        SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection
                    >.convertArgBorrowed(chat) { chatFfi in
                        StringConverter.convertArgBorrowed(number) { numberFfi in
                            ArrayArgConverter<StringConverter, SignalBorrowedSliceOfCStringPtr>.convertArgBorrowed(
                                credentials
                            ) { credentialsFfi in
                                SignalFfi.signal_unauthenticated_chat_connection_check_svr_credentials(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    numberFfi,
                                    credentialsFfi,
                                )
                            }
                        }
                    }
                }
        return try ArrayReturnConverter<
            PairOfResultConverter<
                StringConverter, DerivedReturnConverterAuthCheckResult, SignalPairOfCStringPtrAuthCheckResultFfiResult
            >, SignalOwnedBufferOfMaxAlignedPairOfCStringPtrAuthCheckResultFfiResult
        >.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_create_login_receipt_credential(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        paymentProcessor payment_processor: PaymentProvider,
        purchaseIdentifier purchase_identifier: String,
        receiptCredentialRequestContext receipt_credential_request_context: ReceiptCredentialRequestContext,
        serverParams server_params: ServerPublicParams,
        purchaseTime purchase_time: Date,
        expectedLevel expected_level: LoginReceiptLevel,
    ) async throws -> ReceiptCredential {
        let rawOutput: ByteArrayConverter<ReceiptCredential>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        DerivedArgConverterPaymentProviderInternal.convertArgBorrowed(payment_processor) {
                            payment_processorFfi in
                            StringConverter.convertArgBorrowed(purchase_identifier) { purchase_identifierFfi in
                                ByteArrayConverter<ReceiptCredentialRequestContext>.convertArgBorrowed(
                                    receipt_credential_request_context
                                ) { receipt_credential_request_contextFfi in
                                    BridgeHandleRefConverter<SignalMutPointerServerPublicParams, ServerPublicParams>
                                        .convertArgBorrowed(server_params) { server_paramsFfi in
                                            TimestampConverter.convertArgBorrowed(purchase_time) { purchase_timeFfi in
                                                DerivedArgConverterLoginReceiptLevel.convertArgBorrowed(expected_level)
                                                { expected_levelFfi in
                                                    SignalFfi
                                                        .signal_unauthenticated_chat_connection_create_login_receipt_credential(
                                                            promiseFfi,
                                                            asyncContextFfi.const(),
                                                            chatFfi,
                                                            payment_processorFfi,
                                                            purchase_identifierFfi,
                                                            receipt_credential_request_contextFfi,
                                                            server_paramsFfi,
                                                            purchase_timeFfi,
                                                            expected_levelFfi,
                                                        )
                                                }
                                            }
                                        }
                                }
                            }
                        }
                    }
            }
        return try ByteArrayConverter<ReceiptCredential>.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_delete_avatar(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: AvatarUploadCredentialPresentation,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<AvatarUploadCredentialPresentation>.convertArgBorrowed(credential) {
                            credentialFfi in
                            SignalFfi.signal_unauthenticated_chat_connection_delete_avatar(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                credentialFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_extend_avatar_ttl(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: AvatarUploadCredentialPresentation,
    ) async throws -> CdnUrl? {
        let rawOutput: OptionalReturnConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<AvatarUploadCredentialPresentation>.convertArgBorrowed(credential) {
                            credentialFfi in
                            SignalFfi.signal_unauthenticated_chat_connection_extend_avatar_ttl(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                credentialFfi,
                            )
                        }
                    }
            }
        return try OptionalReturnConverter<CdnUrlConverter, SignalOptionalOfCStringPtr>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func UnauthenticatedChatConnection_get_avatar_upload_form(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        credential: AvatarUploadCredentialPresentation,
        uploadLength upload_length: Int32,
    ) async throws -> S3UploadForm {
        let rawOutput: DerivedReturnConverterS3UploadFormInternal.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        ByteArrayConverter<AvatarUploadCredentialPresentation>.convertArgBorrowed(credential) {
                            credentialFfi in
                            IdentityArgConverter<Int32>.convertArgBorrowed(upload_length) { upload_lengthFfi in
                                SignalFfi.signal_unauthenticated_chat_connection_get_avatar_upload_form(
                                    promiseFfi,
                                    asyncContextFfi.const(),
                                    chatFfi,
                                    credentialFfi,
                                    upload_lengthFfi,
                                )
                            }
                        }
                    }
            }
        return try DerivedReturnConverterS3UploadFormInternal.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_get_profile(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        aci: Aci,
        profileKey profile_key: ProfileKey,
        auth: UnauthProfileAuthorization,
        etag: Data?,
    ) async throws -> FetchedProfile? {
        let rawOutput:
            OptionalReturnConverter<DerivedReturnConverterFetchedProfile, SignalOptionalOfFetchedProfileFfiResult>
                .FfiReturn =
                try await asyncContext.invokeAsyncFunction {
                    promiseFfi,
                    asyncContextFfi in
                    BridgeHandleRefConverter<
                        SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection
                    >.convertArgBorrowed(chat) { chatFfi in
                        AciConverter.convertArgBorrowed(aci) { aciFfi in
                            ByteArrayConverter<ProfileKey>.convertArgBorrowed(profile_key) { profile_keyFfi in
                                DerivedArgConverterUnauthProfileAuthorization.convertArgBorrowed(auth) { authFfi in
                                    OptionalFixedByteArrayConverter<FixedByteArrayHelper10>.convertArgBorrowed(etag) {
                                        etagFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_get_profile(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            aciFfi,
                                            profile_keyFfi,
                                            authFfi,
                                            etagFfi,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
        return try OptionalReturnConverter<
            DerivedReturnConverterFetchedProfile, SignalOptionalOfFetchedProfileFfiResult
        >.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_get_profile_key_credential(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        profileKeyRequestContext profile_key_request_context: ProfileKeyCredentialRequestContext,
        serverParams server_params: ServerPublicParams,
    ) async throws -> ExpiringProfileKeyCredential {
        let rawOutput: FixedLengthSerializedConverter<ExpiringProfileKeyCredential, FixedByteArrayHelper153>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        FixedLengthSerializedConverter<ProfileKeyCredentialRequestContext, FixedByteArrayHelper473>
                            .convertArgBorrowed(profile_key_request_context) { profile_key_request_contextFfi in
                                BridgeHandleRefConverter<SignalMutPointerServerPublicParams, ServerPublicParams>
                                    .convertArgBorrowed(server_params) { server_paramsFfi in
                                        SignalFfi.signal_unauthenticated_chat_connection_get_profile_key_credential(
                                            promiseFfi,
                                            asyncContextFfi.const(),
                                            chatFfi,
                                            profile_key_request_contextFfi,
                                            server_paramsFfi,
                                        )
                                    }
                            }
                    }
            }
        return try FixedLengthSerializedConverter<ExpiringProfileKeyCredential, FixedByteArrayHelper153>.convertReturn(
            consuming: rawOutput
        )

    }
    internal static func UnauthenticatedChatConnection_get_subscription_receipt_credential(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        subscriberId subscriber_id: Data,
        receiptCredentialRequestContext receipt_credential_request_context: ReceiptCredentialRequestContext,
        serverParams server_params: ServerPublicParams,
    ) async throws -> ReceiptCredential {
        let rawOutput: ByteArrayConverter<ReceiptCredential>.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        FixedByteArrayConverter<FixedByteArrayHelper32>.convertArgBorrowed(subscriber_id) {
                            subscriber_idFfi in
                            ByteArrayConverter<ReceiptCredentialRequestContext>.convertArgBorrowed(
                                receipt_credential_request_context
                            ) { receipt_credential_request_contextFfi in
                                BridgeHandleRefConverter<SignalMutPointerServerPublicParams, ServerPublicParams>
                                    .convertArgBorrowed(server_params) { server_paramsFfi in
                                        SignalFfi
                                            .signal_unauthenticated_chat_connection_get_subscription_receipt_credential(
                                                promiseFfi,
                                                asyncContextFfi.const(),
                                                chatFfi,
                                                subscriber_idFfi,
                                                receipt_credential_request_contextFfi,
                                                server_paramsFfi,
                                            )
                                    }
                            }
                        }
                    }
            }
        return try ByteArrayConverter<ReceiptCredential>.convertReturn(consuming: rawOutput)

    }
    internal static func UnauthenticatedChatConnection_submit_call_quality_survey(
        asyncContext: TokioAsyncContext,
        chat: UnauthenticatedChatConnection,
        survey: CallQualitySurvey,
    ) async throws {
        let rawOutput: VoidConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                BridgeHandleRefConverter<SignalMutPointerUnauthenticatedChatConnection, UnauthenticatedChatConnection>
                    .convertArgBorrowed(chat) { chatFfi in
                        DerivedArgConverterCallQualitySurveyInternal.convertArgBorrowed(survey) { surveyFfi in
                            SignalFfi.signal_unauthenticated_chat_connection_submit_call_quality_survey(
                                promiseFfi,
                                asyncContextFfi.const(),
                                chatFfi,
                                surveyFfi,
                            )
                        }
                    }
            }
        return try VoidConverter.convertReturn(consuming: rawOutput)

    }
}
