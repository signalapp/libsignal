//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

package org.signal.libsignal.internal

import org.signal.libsignal.net.internal.BridgeChatListener
import org.signal.libsignal.net.internal.ConnectChatBridge
import org.signal.libsignal.protocol.SignedPublicPreKey
import org.signal.libsignal.protocol.groups.state.SenderKeyStore
import org.signal.libsignal.protocol.logging.Log
import org.signal.libsignal.protocol.logging.SignalProtocolLogger
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyStore
import org.signal.libsignal.protocol.state.PreKeyStore
import org.signal.libsignal.protocol.state.SessionStore
import org.signal.libsignal.protocol.state.SignedPreKeyStore
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.util.Map
import java.util.UUID
import java.util.concurrent.Future

// Public so we can call methods on this from Android on-device test code,
// which behaves differently from unit test code with respect to visibility.
// Once https://youtrack.jetbrains.com/issue/KT-66351 is fixed we can make
// this internal.
public object NativeTesting {
  init {
    // Ensure the Native class is loaded, which means the .so is loaded.
    Native.ensureLoaded()
  }

  @JvmStatic
  public external fun ComparableBackup_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun ComparableBackup_GetComparableString(backup: ObjectHandle): String
  @JvmStatic
  public external fun ComparableBackup_GetUnknownFields(backup: ObjectHandle): Array<Object>
  @JvmStatic @Throws(Exception::class)
  public external fun ComparableBackup_ReadUnencrypted(stream: InputStream, len: Long, purpose: Int): ObjectHandle

  @JvmStatic
  public external fun FakeChatConnection_Destroy(handle: ObjectHandle): Unit

  @JvmStatic
  public external fun FakeChatRemoteEnd_Destroy(handle: ObjectHandle): Unit

  @JvmStatic
  public external fun FakeChatResponse_Destroy(handle: ObjectHandle): Unit

  @JvmStatic
  public external fun FakeChatServer_Destroy(handle: ObjectHandle): Unit

  @JvmStatic
  public external fun OtherTestingHandleType_Destroy(handle: ObjectHandle): Unit

  @JvmStatic @Throws(Exception::class)
  public external fun SessionRecord_GetAliceBaseKey(obj: ObjectHandle): ByteArray

  @JvmStatic
  public external fun TESTING_AcquireSemaphoreAndGet(asyncRuntime: ObjectHandle, semaphore: ObjectHandle, valueHolder: ObjectHandle): CompletableFuture<Int>
  @JvmStatic
  public external fun TESTING_BridgedStringMap_dump_to_json(map: ObjectHandle): String
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_CdsiLookupErrorConvert(errorDescription: String): Unit
  @JvmStatic
  public external fun TESTING_CdsiLookupResponseConvert(asyncRuntime: ObjectHandle): CompletableFuture<Object>
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_ChatConnectErrorConvert(errorDescription: String): Unit
  @JvmStatic
  public external fun TESTING_ChatRequestGetBody(request: ObjectHandle): ByteArray
  @JvmStatic
  public external fun TESTING_ChatRequestGetHeaderNames(request: ObjectHandle): Array<Object>
  @JvmStatic
  public external fun TESTING_ChatRequestGetHeaderValue(request: ObjectHandle, headerName: String): String
  @JvmStatic
  public external fun TESTING_ChatRequestGetMethod(request: ObjectHandle): String
  @JvmStatic
  public external fun TESTING_ChatRequestGetPath(request: ObjectHandle): String
  @JvmStatic
  public external fun TESTING_ChatResponseConvert(bodyPresent: Boolean): Object
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_ChatSendErrorConvert(errorDescription: String): Unit
  @JvmStatic
  public external fun TESTING_ConnectionManager_isUsingProxy(manager: ObjectHandle): Int
  @JvmStatic
  public external fun TESTING_ConvertOptionalUuid(present: Boolean): UUID?
  @JvmStatic
  public external fun TESTING_CreateOTP(username: String, secret: ByteArray): String
  @JvmStatic
  public external fun TESTING_CreateOTPFromBase64(username: String, secret: String): String
  @JvmStatic
  public external fun TESTING_ErrorOnBorrowAsync(input: Object): Unit
  @JvmStatic
  public external fun TESTING_ErrorOnBorrowIo(asyncRuntime: ObjectHandle, input: Object): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_ErrorOnBorrowSync(input: Object): Unit
  @JvmStatic
  public external fun TESTING_ErrorOnReturnAsync(needsCleanup: Object): Object
  @JvmStatic
  public external fun TESTING_ErrorOnReturnIo(asyncRuntime: ObjectHandle, needsCleanup: Object): CompletableFuture<Object>
  @JvmStatic
  public external fun TESTING_ErrorOnReturnSync(needsCleanup: Object): Object
  @JvmStatic
  public external fun TESTING_FakeChatConnection_Create(tokio: ObjectHandle, listener: BridgeChatListener, alertsJoinedByNewlines: String): ObjectHandle
  @JvmStatic
  public external fun TESTING_FakeChatConnection_TakeAuthenticatedChat(chat: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun TESTING_FakeChatConnection_TakeRemote(chat: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun TESTING_FakeChatConnection_TakeUnauthenticatedChat(chat: ObjectHandle): ObjectHandle
  @JvmStatic
  public external fun TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(chat: ObjectHandle): Unit
  @JvmStatic
  public external fun TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(asyncRuntime: ObjectHandle, chat: ObjectHandle): CompletableFuture<Pair<ObjectHandle, Long>?>
  @JvmStatic
  public external fun TESTING_FakeChatRemoteEnd_SendRawServerRequest(chat: ObjectHandle, bytes: ByteArray): Unit
  @JvmStatic
  public external fun TESTING_FakeChatRemoteEnd_SendRawServerResponse(chat: ObjectHandle, bytes: ByteArray): Unit
  @JvmStatic
  public external fun TESTING_FakeChatRemoteEnd_SendServerResponse(chat: ObjectHandle, response: ObjectHandle): Unit
  @JvmStatic
  public external fun TESTING_FakeChatResponse_Create(id: Long, status: Int, message: String, headers: Array<Object>, body: ByteArray?): ObjectHandle
  @JvmStatic
  public external fun TESTING_FakeChatServer_Create(): ObjectHandle
  @JvmStatic
  public external fun TESTING_FakeChatServer_GetNextRemote(asyncRuntime: ObjectHandle, server: ObjectHandle): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun TESTING_FakeRegistrationSession_CreateSession(asyncRuntime: ObjectHandle, createSession: Object, chat: ObjectHandle): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun TESTING_FutureCancellationCounter_Create(initialValue: Int): ObjectHandle
  @JvmStatic
  public external fun TESTING_FutureCancellationCounter_WaitForCount(asyncRuntime: ObjectHandle, count: ObjectHandle, target: Int): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_FutureFailure(asyncRuntime: ObjectHandle, input: Int): CompletableFuture<Int>
  @JvmStatic
  public external fun TESTING_FutureIncrementOnCancel(asyncRuntime: ObjectHandle, guard: Long): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_FutureProducesOtherPointerType(asyncRuntime: ObjectHandle, input: String): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun TESTING_FutureProducesPointerType(asyncRuntime: ObjectHandle, input: Int): CompletableFuture<ObjectHandle>
  @JvmStatic
  public external fun TESTING_FutureSuccess(asyncRuntime: ObjectHandle, input: Int): CompletableFuture<Int>
  @JvmStatic
  public external fun TESTING_FutureThrowsCustomErrorType(asyncRuntime: ObjectHandle): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_FutureThrowsPoisonErrorType(asyncRuntime: ObjectHandle): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_InputStreamReadIntoZeroLengthSlice(capsAlphabetInput: InputStream): ByteArray
  @JvmStatic
  public external fun TESTING_JoinStringArray(array: Array<Object>, joinWith: String): String
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_KeyTransChatSendError(): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_KeyTransFatalVerificationFailure(): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_KeyTransNonFatalVerificationFailure(): Unit
  @JvmStatic
  public external fun TESTING_NonSuspendingBackgroundThreadRuntime_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun TESTING_NonSuspendingBackgroundThreadRuntime_New(): ObjectHandle
  @JvmStatic
  public external fun TESTING_OtherTestingHandleType_getValue(handle: ObjectHandle): String
  @JvmStatic
  public external fun TESTING_PanicInBodyAsync(input: Object): Unit
  @JvmStatic
  public external fun TESTING_PanicInBodyIo(asyncRuntime: ObjectHandle, input: Object): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_PanicInBodySync(input: Object): Unit
  @JvmStatic
  public external fun TESTING_PanicOnBorrowAsync(input: Object): Unit
  @JvmStatic
  public external fun TESTING_PanicOnBorrowIo(asyncRuntime: ObjectHandle, input: Object): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_PanicOnBorrowSync(input: Object): Unit
  @JvmStatic
  public external fun TESTING_PanicOnLoadAsync(needsCleanup: Object, input: Object): Unit
  @JvmStatic
  public external fun TESTING_PanicOnLoadIo(asyncRuntime: ObjectHandle, needsCleanup: Object, input: Object): CompletableFuture<Void?>
  @JvmStatic
  public external fun TESTING_PanicOnLoadSync(needsCleanup: Object, input: Object): Unit
  @JvmStatic
  public external fun TESTING_PanicOnReturnAsync(needsCleanup: Object): Object
  @JvmStatic
  public external fun TESTING_PanicOnReturnIo(asyncRuntime: ObjectHandle, needsCleanup: Object): CompletableFuture<Object>
  @JvmStatic
  public external fun TESTING_PanicOnReturnSync(needsCleanup: Object): Object
  @JvmStatic
  public external fun TESTING_ProcessBytestringArray(input: Array<ByteBuffer>): Array<ByteArray>
  @JvmStatic
  public external fun TESTING_RegisterAccountResponse_CreateTestValue(): ObjectHandle
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_RegistrationService_CheckSvr2CredentialsErrorConvert(errorDescription: String): Unit
  @JvmStatic
  public external fun TESTING_RegistrationService_CheckSvr2CredentialsResponseConvert(): Object
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_RegistrationService_CreateSessionErrorConvert(errorDescription: String): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_RegistrationService_RegisterAccountErrorConvert(errorDescription: String): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_RegistrationService_RequestVerificationCodeErrorConvert(errorDescription: String): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_RegistrationService_ResumeSessionErrorConvert(errorDescription: String): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_RegistrationService_SubmitVerificationErrorConvert(errorDescription: String): Unit
  @JvmStatic @Throws(Exception::class)
  public external fun TESTING_RegistrationService_UpdateSessionErrorConvert(errorDescription: String): Unit
  @JvmStatic
  public external fun TESTING_RegistrationSessionInfoConvert(): ObjectHandle
  @JvmStatic
  public external fun TESTING_ReturnPair(): Pair<Int, String>
  @JvmStatic
  public external fun TESTING_ReturnStringArray(): Array<Object>
  @JvmStatic
  public external fun TESTING_RoundTripI32(input: Int): Int
  @JvmStatic
  public external fun TESTING_RoundTripU16(input: Int): Int
  @JvmStatic
  public external fun TESTING_RoundTripU32(input: Int): Int
  @JvmStatic
  public external fun TESTING_RoundTripU64(input: Long): Long
  @JvmStatic
  public external fun TESTING_RoundTripU8(input: Int): Int
  @JvmStatic
  public external fun TESTING_SignedPublicPreKey_CheckBridgesCorrectly(sourcePublicKey: ObjectHandle, signedPreKey: SignedPublicPreKey<*>): Unit
  @JvmStatic
  public external fun TESTING_TestingHandleType_getValue(handle: ObjectHandle): Int
  @JvmStatic
  public external fun TESTING_TokioAsyncContext_AttachBlockingThreadToJVMPermanently(context: ObjectHandle, jvm: Object): Unit
  @JvmStatic
  public external fun TESTING_TokioAsyncContext_FutureSuccessBytes(asyncRuntime: ObjectHandle, count: Int): CompletableFuture<ByteArray>
  @JvmStatic
  public external fun TESTING_TokioAsyncContext_NewSingleThreaded(): ObjectHandle
  @JvmStatic
  public external fun TESTING_TokioAsyncFuture(asyncRuntime: ObjectHandle, input: Int): CompletableFuture<Int>

  @JvmStatic
  public external fun TestingFutureCancellationCounter_Destroy(handle: ObjectHandle): Unit

  @JvmStatic
  public external fun TestingHandleType_Destroy(handle: ObjectHandle): Unit

  @JvmStatic
  public external fun TestingSemaphore_AddPermits(semaphore: ObjectHandle, permits: Int): Unit
  @JvmStatic
  public external fun TestingSemaphore_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun TestingSemaphore_New(initial: Int): ObjectHandle

  @JvmStatic
  public external fun TestingValueHolder_Destroy(handle: ObjectHandle): Unit
  @JvmStatic
  public external fun TestingValueHolder_Get(holder: ObjectHandle): Int
  @JvmStatic
  public external fun TestingValueHolder_New(value: Int): ObjectHandle

  @JvmStatic
  public external fun test_only_fn_returns_123(): Int
}
