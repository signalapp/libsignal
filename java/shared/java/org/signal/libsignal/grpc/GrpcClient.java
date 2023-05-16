//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.grpc;

import java.util.List;
import java.util.Map;

import org.signal.libsignal.internal.Native;

public class GrpcClient {

  public SignalRpcReply sendMessage(SignalRpcMessage message) {
    return Native.Grpc_SendMessage(message.getMethod(), message.getUrlFragment(), message.getBody(), message.getHeaders());
  }

  public void openStream(String uri, Map<String, List<String>> headers, GrpcReplyListener listener) {
    Native.Grpc_OpenStream(uri, headers, listener);
  }
}
