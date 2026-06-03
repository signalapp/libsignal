//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.util.Arrays;
import java.util.UUID;
import kotlin.Pair;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.net.ChatConnection.InternalRequest;

class FakeChatRemote extends NativeHandleGuard.SimpleOwner {
  public static UUID FAKE_AUTH_CONNECT_SELF_UUID = new UUID(~0, ~0);

  private TokioAsyncContext tokioContext;

  FakeChatRemote(TokioAsyncContext tokioContext, long nativeHandle) {
    super(nativeHandle);
    this.tokioContext = tokioContext;
  }

  @SuppressWarnings("unchecked")
  public CompletableFuture<Pair<InternalRequest, Long>> getNextIncomingRequest() {
    return tokioContext
        .guardedMap(
            asyncContextHandle ->
                this.guardedMap(
                    fakeRemote ->
                        NativeTesting.TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
                            asyncContextHandle, fakeRemote)))
        .thenApply(
            rawRequest -> {
              var sentRequest = (Pair<Long, Long>) rawRequest;
              return new Pair(new InternalRequest(sentRequest.getFirst()), sentRequest.getSecond());
            });
  }

  private class FakeChatResponse extends NativeHandleGuard.SimpleOwner {
    FakeChatResponse(long handle) {
      super(handle);
    }

    protected void release(long nativeHandle) {
      NativeTesting.FakeChatResponse_Destroy(nativeHandle);
    }
  }

  public void sendResponse(
      long requestId, int status, String message, String[] headers, byte[] body) {
    var fakeResponse =
        new FakeChatResponse(
            NativeTesting.TESTING_FakeChatResponse_Create(
                requestId, status, message, headers, body));

    guardedRun(
        fakeRemote ->
            fakeResponse.guardedRun(
                response ->
                    NativeTesting.TESTING_FakeChatRemoteEnd_SendServerResponse(
                        fakeRemote, response)));
  }

  @SuppressWarnings("unchecked")
  public CompletableFuture<Pair<InternalRequest, Long>> getNextIncomingGrpcRequest() {
    return tokioContext
        .guardedMap(
            asyncContextHandle ->
                this.guardedMap(
                    fakeRemote ->
                        NativeTesting.TESTING_FakeChatRemoteEnd_ReceiveIncomingGrpcRequest(
                            asyncContextHandle, fakeRemote)))
        .thenApply(
            rawRequest -> {
              var sentRequest = (Pair<Long, Long>) rawRequest;
              return new Pair(new InternalRequest(sentRequest.getFirst()), sentRequest.getSecond());
            });
  }

  public CompletableFuture<Void> sendGrpcResponse(long requestId, byte[] fullResponse) {
    var fakeResponse =
        new FakeChatResponse(
            NativeTesting.TESTING_FakeChatResponse_Create(
                requestId, 200, "", new Object[0], fullResponse));

    return tokioContext.guardedMap(
        asyncContextHandle ->
            guardedMap(
                fakeRemote ->
                    fakeResponse.guardedMap(
                        response ->
                            NativeTesting.TESTING_FakeChatRemoteEnd_SendServerGrpcResponse(
                                asyncContextHandle, fakeRemote, response))));
  }

  static byte[] encodeSingleGrpcMessage(String name, kotlinx.serialization.json.JsonElement json) {
    var binproto = NativeTesting.TESTING_FakeChatRemoteEnd_JsonToBinproto(name, json.toString());
    var header = NativeTesting.TESTING_FakeChatRemoteEnd_GrpcFrameForMessageLength(binproto.length);
    var result = Arrays.copyOf(header, header.length + binproto.length);
    System.arraycopy(binproto, 0, result, header.length, binproto.length);
    return result;
  }

  public CompletableFuture<Void> sendGrpcResponse(
      long requestId, String name, kotlinx.serialization.json.JsonElement json) {
    return sendGrpcResponse(requestId, encodeSingleGrpcMessage(name, json));
  }

  @Override
  protected void release(long nativeHandle) {
    NativeTesting.FakeChatRemoteEnd_Destroy(nativeHandle);
  }
}
