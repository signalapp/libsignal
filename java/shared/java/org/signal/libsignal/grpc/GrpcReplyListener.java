//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.grpc;

import org.signal.libsignal.internal.CalledFromNative;

@CalledFromNative
public interface GrpcReplyListener {

  void onReply(SignalRpcReply reply);

  void onError(String message);
}
