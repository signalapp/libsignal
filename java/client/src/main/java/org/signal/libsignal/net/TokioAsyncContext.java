//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

class TokioAsyncContext implements NativeHandleGuard.Owner {
  private long nativeHandle;

  TokioAsyncContext() {
    this.nativeHandle = Native.TokioAsyncContext_new();
  }

  @Override
  public long unsafeNativeHandleWithoutGuard() {
    return this.nativeHandle;
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.TokioAsyncContext_Destroy(this.nativeHandle);
  }
}
