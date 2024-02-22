//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public class Network {
  public enum Environment {
    STAGING(0),
    PRODUCTION(1);

    private final int value;

    private Environment(int value) {
      this.value = value;
    }
  }

  /**
   * Group of the APIs responsible for communication with the SVR3 service.
   *
   * <p>Refer to {@link org.signal.libsignal.net.Svr3} for the detailed description.
   */
  private final Svr3 svr3;

  public Network(Environment env) {
    this.tokioAsyncContext = new TokioAsyncContext();
    this.connectionManager = new ConnectionManager(env);
    this.svr3 = new Svr3(this);
  }

  public Svr3 svr3() {
    return this.svr3;
  }

  public CompletableFuture<CdsiLookupResponse> cdsiLookup(
      String username,
      String password,
      CdsiLookupRequest request,
      Duration timeout,
      Consumer<byte[]> tokenConsumer)
      throws IOException, InterruptedException, ExecutionException {
    return CdsiLookup.start(this, username, password, request, timeout)
        .thenCompose(
            (CdsiLookup lookup) -> {
              tokenConsumer.accept(lookup.getToken());
              return lookup.complete();
            });
  }

  TokioAsyncContext getAsyncContext() {
    return this.tokioAsyncContext;
  }

  ConnectionManager getConnectionManager() {
    return this.connectionManager;
  }

  class ConnectionManager implements NativeHandleGuard.Owner {
    private long nativeHandle;

    private ConnectionManager(Environment env) {
      this.nativeHandle = Native.ConnectionManager_new(env.value);
    }

    @Override
    public long unsafeNativeHandleWithoutGuard() {
      return this.nativeHandle;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void finalize() {
      Native.ConnectionManager_Destroy(this.nativeHandle);
    }
  }

  private TokioAsyncContext tokioAsyncContext;
  private ConnectionManager connectionManager;
}
