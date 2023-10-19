//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.grpc;

import java.util.List;
import java.util.Map;

import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class GrpcClient implements NativeHandleGuard.Owner {
  private static final String DEFAULT_TARGET = "https://grpcproxy.gluonhq.net:443";

  private final long unsafeHandle;

  public GrpcClient() {
    this(DEFAULT_TARGET);
  }

  public GrpcClient(String target) {
    this.unsafeHandle = Native.GrpcClient_New(target);
  }

  @Override @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.GrpcClient_Destroy(this.unsafeHandle);
  }

  public long unsafeNativeHandleWithoutGuard() {
    return this.unsafeHandle;
  }

  public byte[] sendDirectMessage(String method, String urlFragment, byte[] body, Map<String, List<String>> headers) {
    return Native.GrpcClient_SendDirectMessage(this.unsafeHandle, method, urlFragment, body, headers);
  }

  public void openStream(String uri, Map<String, List<String>> headers, GrpcReplyListener replyListener) {
    Native.GrpcClient_OpenStream(this.unsafeHandle, uri, headers, replyListener);
  }

  public void sendMessageOnStream(String method, String urlFragment, byte[] body, Map<String, List<String>> headers) {
    Native.GrpcClient_SendMessageOnStream(this.unsafeHandle, method, urlFragment, body, headers);
  }
}
