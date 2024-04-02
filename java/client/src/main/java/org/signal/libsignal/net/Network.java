//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;
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

    Environment(int value) {
      this.value = value;
    }
  }

  private final TokioAsyncContext tokioAsyncContext;

  private final ConnectionManager connectionManager;

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

  /**
   * Sets the proxy host to be used for all new connections (until overridden).
   *
   * <p>Sets a domain name and port to be used to proxy all new outgoing connections. The proxy can
   * be overridden by calling this method again or unset by calling {@link clearProxy}.
   */
  public void setProxy(String host, int port) {
    this.connectionManager.setProxy(host, port);
  }

  /**
   * Ensures that future connections will be made directly, not through a proxy.
   *
   * <p>Clears any proxy configuration set via {@link setProxy}. If none was set, calling this
   * method is a no-op.
   */
  public void clearProxy() {
    this.connectionManager.clearProxy();
  }

  public Svr3 svr3() {
    return this.svr3;
  }

  public CompletableFuture<CdsiLookupResponse> cdsiLookup(
      String username, String password, CdsiLookupRequest request, Consumer<byte[]> tokenConsumer)
      throws IOException, InterruptedException, ExecutionException {
    return CdsiLookup.start(this, username, password, request)
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

  public ChatService createChatService(final String username, final String password) {
    return new ChatService(tokioAsyncContext, connectionManager, username, password);
  }

  static class ConnectionManager extends NativeHandleGuard.SimpleOwner {
    private ConnectionManager(Environment env) {
      super(Native.ConnectionManager_new(env.value));
    }

    private void setProxy(String host, int port) {
      if (port == 0) {
        throw new IllegalArgumentException("Port cannot be zero");
      }
      guardedRun(nativeHandle -> Native.ConnectionManager_set_proxy(nativeHandle, host, port));
    }

    private void clearProxy() {
      guardedRun(Native::ConnectionManager_clear_proxy);
    }

    @Override
    protected void release(final long nativeHandle) {
      Native.ConnectionManager_Destroy(nativeHandle);
    }
  }
}
