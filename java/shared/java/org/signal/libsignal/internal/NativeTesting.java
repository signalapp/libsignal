//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

package org.signal.libsignal.internal;

import org.signal.libsignal.net.internal.BridgeChatListener;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.SessionStore;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;
import org.signal.libsignal.protocol.SignedPublicPreKey;
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.logging.Log;
import org.signal.libsignal.protocol.logging.SignalProtocolLogger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Future;
import java.util.UUID;
import java.util.Map;

public final class NativeTesting {
  static {
    // Ensure the Native class is loaded, which means the .so is loaded.
    Native.ensureLoaded();
  }

  private NativeTesting() {}

  public static native void ComparableBackup_Destroy(long handle);
  public static native String ComparableBackup_GetComparableString(long backup);
  public static native Object[] ComparableBackup_GetUnknownFields(long backup);
  public static native long ComparableBackup_ReadUnencrypted(InputStream stream, long len, int purpose) throws Exception;

  public static native void FakeChatConnection_Destroy(long handle);

  public static native void FakeChatRemoteEnd_Destroy(long handle);

  public static native void FakeChatResponse_Destroy(long handle);

  public static native void FakeChatSentRequest_Destroy(long handle);

  public static native void FakeChatServer_Destroy(long handle);

  public static native void OtherTestingHandleType_Destroy(long handle);

  public static native byte[] SessionRecord_GetAliceBaseKey(long obj) throws Exception;
  public static native byte[] SessionRecord_GetReceiverChainKeyValue(long sessionState, long key) throws Exception;
  public static native byte[] SessionRecord_GetSenderChainKeyValue(long obj) throws Exception;
  public static native byte[] SessionRecord_InitializeAliceSession(long identityKeyPrivate, long identityKeyPublic, long basePrivate, long basePublic, long theirIdentityKey, long theirSignedPrekey, long theirRatchetKey) throws Exception;
  public static native byte[] SessionRecord_InitializeBobSession(long identityKeyPrivate, long identityKeyPublic, long signedPrekeyPrivate, long signedPrekeyPublic, long ephPrivate, long ephPublic, long theirIdentityKey, long theirBaseKey) throws Exception;

  public static native String TESTING_BridgedStringMap_dump_to_json(long map);
  public static native void TESTING_CdsiLookupErrorConvert(String errorDescription) throws Exception;
  public static native CompletableFuture<Object> TESTING_CdsiLookupResponseConvert(long asyncRuntime);
  public static native void TESTING_ChatConnectErrorConvert(String errorDescription) throws Exception;
  public static native byte[] TESTING_ChatRequestGetBody(long request);
  public static native Object[] TESTING_ChatRequestGetHeaderNames(long request);
  public static native String TESTING_ChatRequestGetHeaderValue(long request, String headerName);
  public static native String TESTING_ChatRequestGetMethod(long request);
  public static native String TESTING_ChatRequestGetPath(long request);
  public static native Object TESTING_ChatResponseConvert(boolean bodyPresent);
  public static native long TESTING_ChatSearchResult();
  public static native void TESTING_ChatSendErrorConvert(String errorDescription) throws Exception;
  public static native int TESTING_ConnectionManager_isUsingProxy(long manager);
  public static native void TESTING_ErrorOnBorrowAsync(Object input);
  public static native CompletableFuture TESTING_ErrorOnBorrowIo(long asyncRuntime, Object input);
  public static native void TESTING_ErrorOnBorrowSync(Object input);
  public static native Object TESTING_ErrorOnReturnAsync(Object needsCleanup);
  public static native CompletableFuture<Object> TESTING_ErrorOnReturnIo(long asyncRuntime, Object needsCleanup);
  public static native Object TESTING_ErrorOnReturnSync(Object needsCleanup);
  public static native long TESTING_FakeChatConnection_Create(long tokio, BridgeChatListener listener, String alertsJoinedByNewlines);
  public static native long TESTING_FakeChatConnection_TakeAuthenticatedChat(long chat);
  public static native long TESTING_FakeChatConnection_TakeRemote(long chat);
  public static native long TESTING_FakeChatConnection_TakeUnauthenticatedChat(long chat);
  public static native void TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(long chat);
  public static native CompletableFuture<Long> TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(long asyncRuntime, long chat);
  public static native void TESTING_FakeChatRemoteEnd_SendRawServerRequest(long chat, byte[] bytes);
  public static native void TESTING_FakeChatRemoteEnd_SendRawServerResponse(long chat, byte[] bytes);
  public static native void TESTING_FakeChatRemoteEnd_SendServerResponse(long chat, long response);
  public static native long TESTING_FakeChatResponse_Create(long id, int status, String message, Object[] headers, byte[] body);
  public static native long TESTING_FakeChatSentRequest_RequestId(long request);
  public static native long TESTING_FakeChatSentRequest_TakeHttpRequest(long request);
  public static native long TESTING_FakeChatServer_Create();
  public static native CompletableFuture<Long> TESTING_FakeChatServer_GetNextRemote(long asyncRuntime, long server);
  public static native CompletableFuture<Long> TESTING_FakeRegistrationSession_CreateSession(long asyncRuntime, Object createSession, long chat);
  public static native CompletableFuture<Integer> TESTING_FutureFailure(long asyncRuntime, int input);
  public static native CompletableFuture<Long> TESTING_FutureProducesOtherPointerType(long asyncRuntime, String input);
  public static native CompletableFuture<Long> TESTING_FutureProducesPointerType(long asyncRuntime, int input);
  public static native CompletableFuture<Integer> TESTING_FutureSuccess(long asyncRuntime, int input);
  public static native CompletableFuture<Void> TESTING_FutureThrowsCustomErrorType(long asyncRuntime);
  public static native byte[] TESTING_InputStreamReadIntoZeroLengthSlice(InputStream capsAlphabetInput);
  public static native String TESTING_JoinStringArray(Object[] array, String joinWith);
  public static native void TESTING_NonSuspendingBackgroundThreadRuntime_Destroy(long handle);
  public static native CompletableFuture TESTING_OnlyCompletesByCancellation(long asyncRuntime);
  public static native String TESTING_OtherTestingHandleType_getValue(long handle);
  public static native void TESTING_PanicInBodyAsync(Object input);
  public static native CompletableFuture TESTING_PanicInBodyIo(long asyncRuntime, Object input);
  public static native void TESTING_PanicInBodySync(Object input);
  public static native void TESTING_PanicOnBorrowAsync(Object input);
  public static native CompletableFuture TESTING_PanicOnBorrowIo(long asyncRuntime, Object input);
  public static native void TESTING_PanicOnBorrowSync(Object input);
  public static native void TESTING_PanicOnLoadAsync(Object needsCleanup, Object input);
  public static native CompletableFuture TESTING_PanicOnLoadIo(long asyncRuntime, Object needsCleanup, Object input);
  public static native void TESTING_PanicOnLoadSync(Object needsCleanup, Object input);
  public static native Object TESTING_PanicOnReturnAsync(Object needsCleanup);
  public static native CompletableFuture<Object> TESTING_PanicOnReturnIo(long asyncRuntime, Object needsCleanup);
  public static native Object TESTING_PanicOnReturnSync(Object needsCleanup);
  public static native byte[][] TESTING_ProcessBytestringArray(ByteBuffer[] input);
  public static native long TESTING_RegisterAccountResponse_CreateTestValue();
  public static native void TESTING_RegistrationService_CreateSessionErrorConvert(String errorDescription) throws Exception;
  public static native void TESTING_RegistrationService_RequestVerificationCodeErrorConvert(String errorDescription) throws Exception;
  public static native void TESTING_RegistrationService_ResumeSessionErrorConvert(String errorDescription) throws Exception;
  public static native void TESTING_RegistrationService_SubmitVerificationErrorConvert(String errorDescription) throws Exception;
  public static native void TESTING_RegistrationService_UpdateSessionErrorConvert(String errorDescription) throws Exception;
  public static native long TESTING_RegistrationSessionInfoConvert();
  public static native Object[] TESTING_ReturnStringArray();
  public static native int TESTING_RoundTripI32(int input);
  public static native int TESTING_RoundTripU16(int input);
  public static native int TESTING_RoundTripU32(int input);
  public static native long TESTING_RoundTripU64(long input);
  public static native int TESTING_RoundTripU8(int input);
  public static native void TESTING_SignedPublicPreKey_CheckBridgesCorrectly(long sourcePublicKey, SignedPublicPreKey signedPreKey);
  public static native int TESTING_TestingHandleType_getValue(long handle);

  public static native void TestingHandleType_Destroy(long handle);

  public static native int test_only_fn_returns_123();
}
