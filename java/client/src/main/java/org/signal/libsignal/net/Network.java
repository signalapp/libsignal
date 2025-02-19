//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

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

    // Intentionally package-private to be used in KeyTransparencyClient, without exposing it to the
    // whole world.
    final int value;

    Environment(int value) {
      this.value = value;
    }
  }

  /**
   * The "scheme" for Signal TLS proxies. See {@link #setProxy(String, String, Integer, String,
   * String)}.
   */
  public static final String SIGNAL_TLS_PROXY_SCHEME = "org.signal.tls";

  private final TokioAsyncContext tokioAsyncContext;

  private final ConnectionManager connectionManager;

  public Network(Environment env, String userAgent) {
    this.tokioAsyncContext = new TokioAsyncContext();
    this.connectionManager = new ConnectionManager(env, userAgent);
  }

  /**
   * Sets the proxy host to be used for all new connections (until overridden).
   *
   * <p>Sets a server to be used to proxy all new outgoing connections. The proxy can be overridden
   * by calling this method again or unset by calling {@link #clearProxy}. Passing {@code null} for
   * the {@code port} means the default port for the scheme will be used. {@code username} and
   * {@code password} can be {@code null} as well.
   *
   * <p>To specify a Signal transparent TLS proxy, use {@link SIGNAL_TLS_PROXY_SCHEME}, or the
   * overload that takes a separate domain and port number.
   *
   * <p>Existing connections and services will continue with the setting they were created with. (In
   * particular, changing this setting will not affect any existing {@link ChatConnection
   * ChatConnections}.)
   *
   * @throws IOException if the scheme is unsupported or if the provided parameters are invalid for
   *     that scheme (e.g. Signal TLS proxies don't support authentication)
   */
  public void setProxy(String scheme, String host, Integer port, String username, String password)
      throws IOException {
    this.connectionManager.setProxy(scheme, host, port, username, password);
  }

  /**
   * Sets the Signal TLS proxy host to be used for all new connections (until overridden).
   *
   * <p>Sets a domain name and port to be used to proxy all new outgoing connections, using a Signal
   * transparent TLS proxy. The proxy can be overridden by calling this method again or unset by
   * calling {@link #clearProxy}.
   *
   * <p>Existing connections and services will continue with the setting they were created with. (In
   * particular, changing this setting will not affect any existing {@link ChatConnection
   * ChatConnections}.)
   *
   * @throws IOException if the host or port are not (structurally) valid, such as a port that
   *     doesn't fit in u16.
   */
  public void setProxy(String host, int port) throws IOException {
    // Support <username>@<host> syntax to allow UNENCRYPTED_FOR_TESTING as a marker user.
    // This is not a stable feature of the API and may go away in the future;
    // the Rust layer will reject any other users anyway. But it's convenient for us.
    final int atIndex = host.indexOf('@');
    String username = null;
    if (atIndex != -1) {
      username = host.substring(0, atIndex);
      host = host.substring(atIndex + 1);
    }
    this.connectionManager.setProxy(SIGNAL_TLS_PROXY_SCHEME, host, port, username, null);
  }

  /**
   * Refuses to make any new connections until a new proxy configuration is set or {@link
   * #clearProxy} is called.
   *
   * <p>Existing connections will not be affected.
   */
  public void setInvalidProxy() {
    this.connectionManager.setInvalidProxy();
  }

  /**
   * Ensures that future connections will be made directly, not through a proxy.
   *
   * <p>Clears any proxy configuration set via {@link #setProxy} or {@link #setInvalidProxy}. If
   * none was set, calling this method is a no-op.
   *
   * <p>Existing connections and services will continue with the setting they were created with. (In
   * particular, changing this setting will not affect any existing {@link ChatConnection
   * ChatConnections}.)
   */
  public void clearProxy() {
    this.connectionManager.clearProxy();
  }

  /**
   * Enables or disables censorship circumvention for all new connections (until changed).
   *
   * <p>If CC is enabled, <em>new</em> connections and services may try additional routes to the
   * Signal servers. Existing connections and services will continue with the setting they were
   * created with. (In particular, changing this setting will not affect any existing {@link
   * ChatConnection ChatConnections}.)
   *
   * <p>CC is off by default.
   */
  public void setCensorshipCircumventionEnabled(boolean enabled) {
    this.connectionManager.setCensorshipCircumventionEnabled(enabled);
  }

  /**
   * Notifies libsignal that the network has changed.
   *
   * <p>This will lead to, e.g. caches being cleared and cooldowns being reset.
   */
  public void onNetworkChange() {
    connectionManager.guardedRun(Native::ConnectionManager_on_network_change);
  }

  public CompletableFuture<CdsiLookupResponse> cdsiLookup(
      String username, String password, CdsiLookupRequest request, Consumer<byte[]> tokenConsumer)
      throws IOException, InterruptedException, ExecutionException {
    return this.cdsiLookup(username, password, request, tokenConsumer, false);
  }

  public CompletableFuture<CdsiLookupResponse> cdsiLookup(
      String username,
      String password,
      CdsiLookupRequest request,
      Consumer<byte[]> tokenConsumer,
      boolean useNewConnectLogic)
      throws IOException, InterruptedException, ExecutionException {
    return CdsiLookup.start(this, username, password, request, useNewConnectLogic)
        .thenCompose(
            (CdsiLookup lookup) -> {
              tokenConsumer.accept(lookup.getToken());
              return lookup.complete();
            });
  }

  /**
   * Try to load several libsignal classes asynchronously, using the same mechanism as native (Rust)
   * code.
   *
   * <p>This should only be called in tests, and can be used to ensure at test time that libsignal
   * async code won't fail to load exceptions.
   */
  public static void checkClassesCanBeLoadedAsyncForTest() {
    // This doesn't need to be comprehensive, just check a few classes.
    final String[] classesToLoad = {
      "org.signal.libsignal.net.CdsiLookupResponse$Entry",
      "org.signal.libsignal.net.NetworkException",
      "org.signal.libsignal.net.ChatServiceException",
      "org.signal.libsignal.protocol.ServiceId",
    };
    TokioAsyncContext context = new TokioAsyncContext();

    for (String className : classesToLoad) {
      // No need to do anything with the result; if it doesn't throw, it succeeded.
      try {
        context.loadClassAsync(className).get();
      } catch (ExecutionException | InterruptedException e) {
        throw new RuntimeException(e);
      }
    }
  }

  TokioAsyncContext getAsyncContext() {
    return this.tokioAsyncContext;
  }

  ConnectionManager getConnectionManager() {
    return this.connectionManager;
  }

  /**
   * Initiates an unauthenticated connection attempt to the chat service.
   *
   * <p>The returned {@link CompletableFuture} will resolve when the connection attempt succeeds or
   * fails. If it succeeds, the {@link UnauthenticatedChatConnection} can be used to send requests
   * to the chat service, and incoming events will be provided via the provided {@link
   * ChatConnectionListener} argument.
   *
   * <p>If the connection attempt fails, the future will contain a {@link ChatServiceException} or
   * other exception type wrapped in a {@link ExecutionException}.
   */
  public CompletableFuture<UnauthenticatedChatConnection> connectUnauthChat(
      ChatConnectionListener listener) {
    return UnauthenticatedChatConnection.connect(tokioAsyncContext, connectionManager, listener);
  }

  /**
   * Initiates an authenticated connection attempt to the chat service.
   *
   * <p>The returned {@link CompletableFuture} will resolve when the connection attempt succeeds or
   * fails. If it succeeds, the {@link AuthenticatedChatConnection} can be used to send requests to
   * the chat service, and incoming events will be provided via the provided {@link
   * ChatConnectionListener} argument.
   *
   * <p>If the connection attempt fails, the future will contain a {@link ChatServiceException} or
   * other exception type wrapped in a {@link ExecutionException}.
   */
  public CompletableFuture<AuthenticatedChatConnection> connectAuthChat(
      final String username,
      final String password,
      final boolean receiveStories,
      ChatConnectionListener listener) {
    return AuthenticatedChatConnection.connect(
        tokioAsyncContext, connectionManager, username, password, receiveStories, listener);
  }

  static class ConnectionManager extends NativeHandleGuard.SimpleOwner {
    private final Environment environment;

    private ConnectionManager(Environment env, String userAgent) {
      super(Native.ConnectionManager_new(env.value, userAgent));
      this.environment = env;
    }

    private void setProxy(
        String scheme, String host, Integer port, String username, String password)
        throws IOException {
      long rawProxyConfig;
      try {
        rawProxyConfig =
            filterExceptions(
                IOException.class,
                () ->
                    Native.ConnectionProxyConfig_new(
                        scheme,
                        host,
                        // Integer.MIN_VALUE represents "no port provided"; we don't expect anyone
                        // to pass that manually.
                        port != null ? port : Integer.MIN_VALUE,
                        username,
                        password));
      } catch (IOException | RuntimeException | Error e) {
        setInvalidProxy();
        throw e;
      }

      try {
        guardedRun(h -> Native.ConnectionManager_set_proxy(h, rawProxyConfig));
      } finally {
        Native.ConnectionProxyConfig_Destroy(rawProxyConfig);
      }
    }

    private void setInvalidProxy() {
      guardedRun(Native::ConnectionManager_set_invalid_proxy);
    }

    private void clearProxy() {
      guardedRun(Native::ConnectionManager_clear_proxy);
    }

    public Environment environment() {
      return this.environment;
    }

    private void setCensorshipCircumventionEnabled(boolean enabled) {
      guardedRun(h -> Native.ConnectionManager_set_censorship_circumvention_enabled(h, enabled));
    }

    @Override
    protected void release(final long nativeHandle) {
      Native.ConnectionManager_Destroy(nativeHandle);
    }
  }
}
