//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.grpc;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.signal.libsignal.internal.Native;

public class GrpcClient {

  public SignalRpcReply sendMessage(SignalRpcMessage message) {
    byte[] reply = Native.Grpc_SendMessage(message.getMethod(), message.getUrlFragment(), message.getBody(), message.getHeaders());

    SignalRpcReply signalRpcReply = new SignalRpcReply();

    ByteBuffer replyBuffer = ByteBuffer.wrap(reply, 0, 4);
    signalRpcReply.setStatusCode(replyBuffer.getInt());

    signalRpcReply.setMessage(new String(reply, 4, reply.length - 4, StandardCharsets.UTF_8));
    return signalRpcReply;
  }
}
