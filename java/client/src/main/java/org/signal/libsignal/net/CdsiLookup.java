//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

class CdsiLookup implements NativeHandleGuard.Owner {
  public static CompletableFuture<CdsiLookup> start(
      Network network,
      String username,
      String password,
      CdsiLookupRequest request,
      Duration timeout)
      throws IOException, InterruptedException, ExecutionException {

    int timeoutMillis;
    try {
      timeoutMillis = Math.toIntExact(timeout.toMillis());
    } catch (ArithmeticException e) {
      timeoutMillis = Integer.MAX_VALUE;
    }

    CdsiLookupRequest.NativeRequest nativeRequest = request.makeNative();
    try (NativeHandleGuard asyncRuntime = new NativeHandleGuard(network.getAsyncContext());
        NativeHandleGuard connectionManager =
            new NativeHandleGuard(network.getConnectionManager())) {

      return Native.CdsiLookup_new(
              asyncRuntime.nativeHandle(),
              connectionManager.nativeHandle(),
              username,
              password,
              nativeRequest.getHandle(),
              timeoutMillis)
          .thenApply((Long nativeHandle) -> new CdsiLookup(nativeHandle, network));
    }
  }

  public CompletableFuture<CdsiLookupResponse> complete() {
    // The output from the bridging layer is untyped, but we're pretty sure it's
    // a map from E164 strings to typed entries.
    @SuppressWarnings("unchecked")
    Function<Map, CdsiLookupResponse> convertResponse =
        (Map untypedResult) ->
            new CdsiLookupResponse((Map<String, CdsiLookupResponse.Entry>) (untypedResult));

    try (NativeHandleGuard asyncRuntime = new NativeHandleGuard(this.network.getAsyncContext());
        NativeHandleGuard self = new NativeHandleGuard(this)) {
      return Native.CdsiLookup_complete(asyncRuntime.nativeHandle(), self.nativeHandle())
          .thenApply(convertResponse);
    }
  }

  public byte[] getToken() {
    return Native.CdsiLookup_token(this.nativeHandle);
  }

  @Override
  public long unsafeNativeHandleWithoutGuard() {
    return this.nativeHandle;
  }

  private CdsiLookup(long nativeHandle, Network network) {
    this.nativeHandle = nativeHandle;
    this.network = network;
  }

  private Network network;
  private long nativeHandle;

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.CdsiLookup_Destroy(this.nativeHandle);
  }
}
