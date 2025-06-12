//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.internal.TokioAsyncContext;

class FakeChatServer extends NativeHandleGuard.SimpleOwner {
  private TokioAsyncContext tokioContext;

  public FakeChatServer(TokioAsyncContext tokioContext) {
    this(tokioContext, NativeTesting.TESTING_FakeChatServer_Create());
  }

  private FakeChatServer(TokioAsyncContext tokioContext, long nativeHandle) {
    super(nativeHandle);
    this.tokioContext = tokioContext;
  }

  public TokioAsyncContext getTokioContext() {
    return this.tokioContext;
  }

  public CompletableFuture<FakeChatRemote> getNextRemote() {
    return tokioContext
        .guardedMap(
            asyncContextHandle ->
                this.guardedMap(
                    fakeServer ->
                        NativeTesting.TESTING_FakeChatServer_GetNextRemote(
                            asyncContextHandle, fakeServer)))
        .thenApply(fakeRemote -> new FakeChatRemote(tokioContext, fakeRemote));
  }

  @Override
  protected void release(long nativeHandle) {
    NativeTesting.FakeChatServer_Destroy(nativeHandle);
  }
}
