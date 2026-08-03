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

extension SignalCPromisec_uchar32: SignalCPromise {

    typealias Result = SignalType_FixedArray32_uint8_t

    init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalType_FixedArray32_uint8_t_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalType_FixedArray32_uint8_t_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_bool_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_bool_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiCdsiLookupResponse_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiCdsiLookupResponse_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiChatResponse_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiChatResponse_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiCheckSvr2CredentialsResponse_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiCheckSvr2CredentialsResponse_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiPreKeysResponse_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiPreKeysResponse_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiUploadForm_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalFfiUploadForm_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerCdsiLookup_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerCdsiLookup_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerAuthenticatedChatConnection_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerAuthenticatedChatConnection_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerProvisioningChatConnection_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerProvisioningChatConnection_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerUnauthenticatedChatConnection_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerUnauthenticatedChatConnection_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerRegistrationService_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerRegistrationService_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerBackupRestoreResponse_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerBackupRestoreResponse_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerBackupStoreResponse_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerBackupStoreResponse_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerRegisterAccountResponse_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalMutPointerRegisterAccountResponse_SignalType_ConstPointer_void?
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

extension SignalCPromiseOptionalPairOfCStringPtrc_uchar32: SignalCPromise {

    typealias Result = SignalOptionalPairOfCStringPtrc_uchar32

    init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOptionalPairOfCStringPtrc_uchar32_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOptionalPairOfCStringPtrc_uchar32_SignalType_ConstPointer_void?
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

extension SignalCPromiseOptionalUuid: SignalCPromise {

    typealias Result = SignalOptionalUuid

    init(
        generic_complete:
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOptionalUuid_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOptionalUuid_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOwnedBufferOfc_uchar17_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOwnedBufferOfc_uchar17_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOwnedBuffer_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOwnedBuffer_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalPairOfCStringPtrCStringPtr_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalPairOfCStringPtrCStringPtr_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalPairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalPairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalPairOfOwnedBufferOwnedBuffer_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalPairOfOwnedBufferOwnedBuffer_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalUuid_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalUuid_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalBridgeMediaBackupInfoFfiResult_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalBridgeMediaBackupInfoFfiResult_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalBridgeMessageBackupInfoFfiResult_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalBridgeMessageBackupInfoFfiResult_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalCopyBackupMediaNextChunkFfiResult_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalCopyBackupMediaNextChunkFfiResult_SignalType_ConstPointer_void?
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
            SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalDeleteBackupMediaNextChunkFfiResult_SignalType_ConstPointer_void?,
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
        SignalType_FunctionPointer_void_SignalType_MutPointer_SignalFfiError_SignalType_ConstPointer_SignalDeleteBackupMediaNextChunkFfiResult_SignalType_ConstPointer_void?
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

enum
    FfiBorrowedSliceConstructor_SignalBorrowedSliceOfBridgeCopyBackupMediaItemFfiArg_DerivedArgConverterBridgeCopyBackupMediaItem:
        FfiBorrowedSliceConstructor
{
    typealias BorrowedSlice = SignalFfi.SignalBorrowedSliceOfBridgeCopyBackupMediaItemFfiArg
    typealias Element = DerivedArgConverterBridgeCopyBackupMediaItem.FfiArg
    static func construct(
        _ buffer: UnsafeBufferPointer<Element>,
    ) -> BorrowedSlice {
        BorrowedSlice(base: buffer.baseAddress, length: buffer.count)
    }
}

enum
    FfiBorrowedSliceConstructor_SignalBorrowedSliceOfBridgeDeleteBackupMediaItemFfiArg_DerivedArgConverterBridgeDeleteBackupMediaItem:
        FfiBorrowedSliceConstructor
{
    typealias BorrowedSlice = SignalFfi.SignalBorrowedSliceOfBridgeDeleteBackupMediaItemFfiArg
    typealias Element = DerivedArgConverterBridgeDeleteBackupMediaItem.FfiArg
    static func construct(
        _ buffer: UnsafeBufferPointer<Element>,
    ) -> BorrowedSlice {
        BorrowedSlice(base: buffer.baseAddress, length: buffer.count)
    }
}

enum FfiBorrowedSliceConstructor_SignalBorrowedSliceOfc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32:
    FfiBorrowedSliceConstructor
{
    typealias BorrowedSlice = SignalFfi.SignalBorrowedSliceOfc_uchar32
    typealias Element = FixedByteArrayConverter<FixedByteArrayHelper32>.FfiArg
    static func construct(
        _ buffer: UnsafeBufferPointer<Element>,
    ) -> BorrowedSlice {
        BorrowedSlice(base: buffer.baseAddress, length: buffer.count)
    }
}

enum
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult_DerivedReturnConverterBridgeCopyBackupMediaItem:
        FfiOwnedBufferOfMaxAlignedProject
{
    typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult
    typealias Element = DerivedReturnConverterBridgeCopyBackupMediaItem.FfiReturn
    static func empty() -> Buffer {
        Buffer()
    }
    static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    static func typeErased(
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
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaOutcomeFfiResult_DerivedReturnConverterBridgeCopyBackupMediaOutcome:
        FfiOwnedBufferOfMaxAlignedProject
{
    typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaOutcomeFfiResult
    typealias Element = DerivedReturnConverterBridgeCopyBackupMediaOutcome.FfiReturn
    static func empty() -> Buffer {
        Buffer()
    }
    static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    static func typeErased(
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
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeDeleteBackupMediaItemFfiResult_DerivedReturnConverterBridgeDeleteBackupMediaItem:
        FfiOwnedBufferOfMaxAlignedProject
{
    typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedBridgeDeleteBackupMediaItemFfiResult
    typealias Element = DerivedReturnConverterBridgeDeleteBackupMediaItem.FfiReturn
    static func empty() -> Buffer {
        Buffer()
    }
    static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    static func typeErased(
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
    FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_DerivedReturnConverterLinkedDeviceInternal:
        FfiOwnedBufferOfMaxAlignedProject
{
    typealias Buffer = SignalFfi.SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult
    typealias Element = DerivedReturnConverterLinkedDeviceInternal.FfiReturn
    static func empty() -> Buffer {
        Buffer()
    }
    static func project(
        _ buffer: Buffer
    ) -> UnsafeBufferPointer<Element> {
        UnsafeBufferPointer(start: buffer.base, count: buffer.length)
    }
    static func typeErased(
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

internal struct CopyBackupMediaNextChunk {
    var chunk: [BridgeCopyBackupMediaOutcome]
    var termination: BulkPolledStreamTermination?

}

internal struct DeleteBackupMediaNextChunk {
    var chunk: [BridgeDeleteBackupMediaItem]
    var termination: BulkPolledStreamTermination?

}

internal struct LinkedDeviceInternal {
    var id: DeviceId
    var encryptedName: Data
    var lastSeen: Date
    var registrationId: UInt16
    var createdAtCiphertext: Data

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
                try IdentityConverter<Int32>.convertReturn(
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
        let cdn = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.cdn) }

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
        let used_space = Result { try IdentityConverter<Int64>.convertReturn(consuming: ffiValue.used_space) }

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
        let cdn = Result { try IdentityConverter<Int32>.convertReturn(consuming: ffiValue.cdn) }
        let backup_name = Result { try StringConverter.convertReturn(consuming: ffiValue.backup_name) }

        return BridgeMessageBackupInfo(
            backupDir: try backup_dir.get(),
            cdn: try cdn.get(),
            backupName: try backup_name.get()
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
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaOutcomeFfiResult_DerivedReturnConverterBridgeCopyBackupMediaOutcome
            >.convertReturn(consuming: ffiValue.chunk)
        }
        let termination = Result {
            try BulkPolledStreamTerminationConverter.convertReturn(consuming: ffiValue.termination)
        }

        return CopyBackupMediaNextChunk(chunk: try chunk.get(), termination: try termination.get())
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
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeDeleteBackupMediaItemFfiResult_DerivedReturnConverterBridgeDeleteBackupMediaItem
            >.convertReturn(consuming: ffiValue.chunk)
        }
        let termination = Result {
            try BulkPolledStreamTerminationConverter.convertReturn(consuming: ffiValue.termination)
        }

        return DeleteBackupMediaNextChunk(chunk: try chunk.get(), termination: try termination.get())
    }
}

internal enum DerivedReturnConverterLinkedDeviceInternal: NiceReturnConverter {
    typealias NiceReturn = LinkedDeviceInternal
    typealias FfiReturn = SignalLinkedDeviceInternalFfiResult
    static func emptyFfiReturn() -> FfiReturn {
        SignalLinkedDeviceInternalFfiResult()
    }
    static func convertReturn(consuming ffiValue: FfiReturn) throws -> NiceReturn {

        let id = Result { try DeviceIdConverter.convertReturn(consuming: ffiValue.id) }
        let encrypted_name = Result { try DataConverter.convertReturn(consuming: ffiValue.encrypted_name) }
        let last_seen = Result { try TimestampConverter.convertReturn(consuming: ffiValue.last_seen) }
        let registration_id = Result {
            try IdentityConverter<UInt16>.convertReturn(consuming: ffiValue.registration_id)
        }
        let created_at_ciphertext = Result {
            try DataConverter.convertReturn(consuming: ffiValue.created_at_ciphertext)
        }

        return LinkedDeviceInternal(
            id: try id.get(),
            encryptedName: try encrypted_name.get(),
            lastSeen: try last_seen.get(),
            registrationId: try registration_id.get(),
            createdAtCiphertext: try created_at_ciphertext.get()
        )
    }
}

internal enum DerivedArgConverterBridgeCopyBackupMediaItem: NiceArgConverter {
    typealias NiceArg = BridgeCopyBackupMediaItem
    typealias FfiArg = SignalBridgeCopyBackupMediaItemFfiArg

    typealias KeepAlive = (
        IdentityConverter<Int32>.KeepAlive?, StringConverter.KeepAlive?, IdentityConverter<Int64>.KeepAlive?,
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
                IdentityConverter<Int32>.FfiArg,
                IdentityConverter<Int32>.KeepAlive?,
            ) = IdentityConverter<Int32>.convertArg(source_attachment_cdn)
        let (source_key_ffi, source_key_keepalive):
            (
                StringConverter.FfiArg,
                StringConverter.KeepAlive?,
            ) = StringConverter.convertArg(source_key)
        let (object_length_ffi, object_length_keepalive):
            (
                IdentityConverter<Int64>.FfiArg,
                IdentityConverter<Int64>.KeepAlive?,
            ) = IdentityConverter<Int64>.convertArg(object_length)
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
                IdentityConverter<Int32>.KeepAlive?, StringConverter.KeepAlive?, IdentityConverter<Int64>.KeepAlive?,
                FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?,
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

        return try IdentityConverter<Int32>.convertArgBorrowed(source_attachment_cdn) {
            ffi_source_attachment_cdn in
            return try StringConverter.convertArgBorrowed(source_key) {
                ffi_source_key in
                return try IdentityConverter<Int64>.convertArgBorrowed(object_length) {
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
        FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?,
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
                IdentityConverter<Int32>.FfiArg,
                IdentityConverter<Int32>.KeepAlive?,
            ) = IdentityConverter<Int32>.convertArg(cdn)

        let ffiStructArg = FfiArg(media_id: media_id_ffi, cdn: cdn_ffi, )
        let ffiStructKeepAlive:
            (FixedByteArrayConverter<FixedByteArrayHelper15>.KeepAlive?, IdentityConverter<Int32>.KeepAlive?, )? =
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
            return try IdentityConverter<Int32>.convertArgBorrowed(cdn) {
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

internal enum NativeNice {
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
    internal static func AuthenticatedChatConnection_get_devices(
        asyncContext: TokioAsyncContext,
        chat: AuthenticatedChatConnection,
    ) async throws -> [LinkedDeviceInternal] {
        let rawOutput:
            ArrayReturnConverter<
                DerivedReturnConverterLinkedDeviceInternal,
                FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_DerivedReturnConverterLinkedDeviceInternal
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
            DerivedReturnConverterLinkedDeviceInternal,
            FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedLinkedDeviceInternalFfiResult_DerivedReturnConverterLinkedDeviceInternal
        >.convertReturn(consuming: rawOutput)

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
                            FixedByteArrayConverter<FixedByteArrayHelper32>,
                            FfiBorrowedSliceConstructor_SignalBorrowedSliceOfc_uchar32_FixedByteArrayConverterFixedByteArrayHelper32
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
                        IdentityConverter<Bool>.convertArgBorrowed(discoverable) { discoverableFfi in
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
                            IdentityConverter<Bool>.convertArgBorrowed(keep_link_handle) { keep_link_handleFfi in
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
    internal static func CopyBackupMediaStream_forceEmitVecOfBridgeCopyBackupMediaItem() throws
        -> [BridgeCopyBackupMediaItem]
    {
        var rawOutput = ArrayReturnConverter<
            DerivedReturnConverterBridgeCopyBackupMediaItem,
            FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult_DerivedReturnConverterBridgeCopyBackupMediaItem
        >.emptyFfiReturn()
        try checkError(
            SignalFfi.signal_copy_backup_media_stream_force_emit_vec_of_bridge_copy_backup_media_item(
                &rawOutput,
            )
        )
        return try ArrayReturnConverter<
            DerivedReturnConverterBridgeCopyBackupMediaItem,
            FfiOwnedBufferOfMaxAlignedProject_SignalOwnedBufferOfMaxAlignedBridgeCopyBackupMediaItemFfiResult_DerivedReturnConverterBridgeCopyBackupMediaItem
        >.convertReturn(consuming: rawOutput)

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
        let rawOutput: IdentityConverter<Bool>.FfiReturn =
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
        return try IdentityConverter<Bool>.convertReturn(consuming: rawOutput)

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
                                FfiBorrowedSliceConstructor_SignalBorrowedSliceOfBridgeCopyBackupMediaItemFfiArg_DerivedArgConverterBridgeCopyBackupMediaItem
                            >.convertArgBorrowed(items) { itemsFfi in
                                try IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                FfiBorrowedSliceConstructor_SignalBorrowedSliceOfBridgeDeleteBackupMediaItemFfiArg_DerivedArgConverterBridgeDeleteBackupMediaItem
                            >.convertArgBorrowed(items) { itemsFfi in
                                try IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                    IdentityConverter<Int32>.convertArgBorrowed(cdn) { cdnFfi in
                                        IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
                                    IdentityConverter.convertArgBorrowed(rng) { rngFfi in
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
}
