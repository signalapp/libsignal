//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

class CdsiLookup implements NativeHandleGuard.Owner {
  public static CompletableFuture<CdsiLookup> start(
      Network network, String username, String password, CdsiLookupRequest request)
      throws IOException, InterruptedException, ExecutionException {
    return CdsiLookup.start(network, username, password, request, false);
  }

  public static CompletableFuture<CdsiLookup> start(
      Network network,
      String username,
      String password,
      CdsiLookupRequest request,
      boolean useNewConnectLogic)
      throws IOException, InterruptedException, ExecutionException {

    interface StartCdsiLookup {
      CompletableFuture<Long> invoke(
          long asyncRuntime,
          long connectionManager,
          String username,
          String password,
          long nativeRequest);
    }

    StartCdsiLookup startLookup =
        useNewConnectLogic ? Native::CdsiLookup_new_routes : Native::CdsiLookup_new;

    CdsiLookupRequest.NativeRequest nativeRequest = request.makeNative();
    try (NativeHandleGuard asyncRuntime = new NativeHandleGuard(network.getAsyncContext());
        NativeHandleGuard connectionManager =
            new NativeHandleGuard(network.getConnectionManager())) {

      return startLookup
          .invoke(
              asyncRuntime.nativeHandle(),
              connectionManager.nativeHandle(),
              username,
              password,
              nativeRequest.getHandle())
          .thenApply((Long nativeHandle) -> new CdsiLookup(nativeHandle, network));
    }
  }

  public CompletableFuture<CdsiLookupResponse> complete() {
    try (NativeHandleGuard asyncRuntime = new NativeHandleGuard(this.network.getAsyncContext());
        NativeHandleGuard self = new NativeHandleGuard(this)) {
      return Native.CdsiLookup_complete(asyncRuntime.nativeHandle(), self.nativeHandle())
          .thenApply(response -> (CdsiLookupResponse) response);
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
