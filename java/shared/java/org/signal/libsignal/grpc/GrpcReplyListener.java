//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.grpc;

public interface GrpcReplyListener {

  void onReply(SignalRpcReply reply);

  void onError(String message);
}
