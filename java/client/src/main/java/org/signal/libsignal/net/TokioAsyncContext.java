//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

class TokioAsyncContext extends NativeHandleGuard.SimpleOwner {
  TokioAsyncContext() {
    super(Native.TokioAsyncContext_new());
  }

  @SuppressWarnings("unchecked")
  CompletableFuture<Class<Object>> loadClassAsync(String className) {
    return (CompletableFuture<Class<Object>>) Native.AsyncLoadClass(this, className);
  }

  @Override
  protected void release(final long nativeHandle) {
    Native.TokioAsyncContext_Destroy(nativeHandle);
  }
}
