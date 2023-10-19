//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.quic;

import java.util.Map;

import org.signal.libsignal.internal.Native;

public class QuicClient {
  private static final String DEFAULT_TARGET = "grpcproxy.gluonhq.net:7443";

  private final long unsafeHandle;

  public QuicClient() {
    this(DEFAULT_TARGET);
  }

  public QuicClient(String target) {
    this.unsafeHandle = Native.QuicClient_New(target);
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.QuicClient_Destroy(this.unsafeHandle);
  }
  
  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public byte[] sendMessage(byte[] data) {
    return Native.QuicClient_SendMessage(this.unsafeHandle, data);
  }

  public void openControlledStream(String baseUrl, Map<String, String> headers, QuicCallbackListener listener) {
    Native.QuicClient_OpenControlledStream(this.unsafeHandle, baseUrl, headers, listener);
  }

  public void writeMessageOnStream(byte[] payload) {
    Native.QuicClient_WriteMessageOnStream(this.unsafeHandle, payload);
  }
}
