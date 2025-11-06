//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import kotlin.Pair;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.net.ChatConnection.InternalRequest;

class FakeChatRemote extends NativeHandleGuard.SimpleOwner {
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

  public void sendResponse(
      long requestId, int status, String message, String[] headers, byte[] body) {
    var fakeResponse =
        new NativeHandleGuard.SimpleOwner(
            NativeTesting.TESTING_FakeChatResponse_Create(
                requestId, status, message, headers, body)) {
          protected void release(long nativeHandle) {
            NativeTesting.FakeChatResponse_Destroy(nativeHandle);
          }
        };

    guardedRun(
        fakeRemote ->
            fakeResponse.guardedRun(
                response ->
                    NativeTesting.TESTING_FakeChatRemoteEnd_SendServerResponse(
                        fakeRemote, response)));
  }

  @Override
  protected void release(long nativeHandle) {
    NativeTesting.FakeChatRemoteEnd_Destroy(nativeHandle);
  }
}
