//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.io.IOException;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import org.signal.libsignal.internal.BridgedStringMap;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.net.internal.ConnectChatBridge;

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
   * Build variant for remote config key selection.
   *
   * <p>This enum must be kept in sync with the Rust version.
   *
   * <ul>
   *   <li>{@link #PRODUCTION}: Use for release builds or any build that may become a release build
   *       (e.g., beta builds on Android). Only uses base remote config keys without suffixes.
   *   <li>{@link #BETA}: Use for all other builds (nightly, alpha, internal, public betas). Prefers
   *       keys with a {@code .beta} suffix, falling back to base keys if the suffixed key is not
   *       present.
   * </ul>
   */
  public enum BuildVariant {
    PRODUCTION(0),
    BETA(1);

    final int value;

    BuildVariant(int value) {
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

  /**
   * @deprecated Use {@link #Network(Environment, String, Map, BuildVariant)} instead, explicitly
   *     specifying BuildVariant.PRODUCTION or BuildVariant.BETA.
   */
  @Deprecated
  public Network(Environment env, String userAgent) {
    this(env, userAgent, Collections.emptyMap(), BuildVariant.PRODUCTION);
  }

  /**
   * @deprecated Use {@link #Network(Environment, String, Map, BuildVariant)} instead, explicitly
   *     specifying BuildVariant.PRODUCTION or BuildVariant.BETA.
   */
  @Deprecated
  public Network(Environment env, String userAgent, Map<String, String> remoteConfig) {
    this(env, userAgent, remoteConfig, BuildVariant.PRODUCTION);
  }

  public Network(
      Environment env,
      String userAgent,
      Map<String, String> remoteConfig,
      BuildVariant buildVariant) {
    this.tokioAsyncContext = new TokioAsyncContext();
    this.connectionManager = new ConnectionManager(env, userAgent, remoteConfig, buildVariant);
  }

  /**
   * Get the SVR-B (Secure Value Recovery for Backups) service for this network instance.
   *
   * @param username The username for authenticating with the SVR-B service.
   * @param password The password for authenticating with the SVR-B service.
   * @return An SvrB service instance configured for this network environment.
   */
  public SvrB svrB(String username, String password) {
    return new SvrB(this, username, password);
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
   * Updates libsignal's remote configuration settings with the specified build variant.
   *
   * <p>The provided configuration map must conform to the following requirements:
   *
   * <ul>
   *   <li>Each key represents an enabled configuration and directly indicates that the setting is
   *       enabled.
   *   <li>Keys must have had the platform-specific prefix (e.g., "android.libsignal.") removed.
   *   <li>Entries explicitly disabled by the server must not appear in the map.
   *   <li>Values originally set to {@code null} by the server must be represented as empty strings.
   *   <li>Values should otherwise maintain the same format as they are returned by the server.
   * </ul>
   *
   * <p>These constraints ensure configurations passed to libsignal precisely reflect enabled
   * server-provided settings, without ambiguity.
   *
   * <p>Only new connections made *after* this call will use the new remote config settings.
   * Existing connections are not affected.
   *
   * @param remoteConfig a map containing preprocessed libsignal configuration keys and their
   *     associated values
   * @param buildVariant the build variant (Production or Beta) that determines which remote config
   *     keys to use
   */
  public void setRemoteConfig(Map<String, String> remoteConfig, BuildVariant buildVariant) {
    this.connectionManager.setRemoteConfig(remoteConfig, buildVariant);
  }

  /**
   * Updates libsignal's remote configuration settings using Production build variant.
   *
   * <p>This is a backwards-compatible overload that defaults to Production.
   *
   * @param remoteConfig a map containing preprocessed libsignal configuration keys and their
   *     associated values
   * @deprecated Use {@link #setRemoteConfig(Map, BuildVariant)} instead, explicitly specifying
   *     BuildVariant.PRODUCTION or BuildVariant.BETA.
   */
  @Deprecated
  public void setRemoteConfig(Map<String, String> remoteConfig) {
    this.setRemoteConfig(remoteConfig, BuildVariant.PRODUCTION);
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
    return CdsiLookup.start(this, username, password, request)
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
   * Starts the process of connecting to the chat server.
   *
   * <p>If this completes successfully, the next call to {@link #connectAuthChat} may be able to
   * finish more quickly. If it's incomplete or produces an error, such a call will start from
   * scratch as usual. Only one preconnect is recorded, so there's no point in calling this more
   * than once.
   */
  public CompletableFuture<Void> preconnectChat() {
    return tokioAsyncContext.guardedMap(
        asyncContext ->
            connectionManager.guardedMap(
                connectionManager ->
                    Native.AuthenticatedChatConnection_preconnect(
                        asyncContext, connectionManager)));
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
      final Locale locale, ChatConnectionListener listener) {
    return UnauthenticatedChatConnection.connect(
        tokioAsyncContext, connectionManager, locale, listener);
  }

  /**
   * Calls {@link #connectUnauthChat(Locale, ChatConnectionListener)} with no connection-level
   * locale.
   */
  public CompletableFuture<UnauthenticatedChatConnection> connectUnauthChat(
      ChatConnectionListener listener) {
    return connectUnauthChat(null, listener);
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
      final Locale locale,
      ChatConnectionListener listener) {
    return AuthenticatedChatConnection.connect(
        tokioAsyncContext, connectionManager, username, password, receiveStories, locale, listener);
  }

  /**
   * Calls {@link #connectAuthChat(String, String, boolean, Locale, ChatConnectionListener)} with no
   * connection-level locale.
   */
  public CompletableFuture<AuthenticatedChatConnection> connectAuthChat(
      final String username,
      final String password,
      final boolean receiveStories,
      ChatConnectionListener listener) {
    return connectAuthChat(username, password, receiveStories, null, listener);
  }

  static String[] languageCodesForLocale(Locale locale) {
    return locale == null
        ? new String[0]
        : new String[] {locale.getLanguage() + "-" + locale.getCountry()};
  }

  static class ConnectionManager extends NativeHandleGuard.SimpleOwner
      implements ConnectChatBridge {
    private final Environment environment;

    private ConnectionManager(
        Environment env,
        String userAgent,
        Map<String, String> remoteConfig,
        BuildVariant buildVariant) {
      super(
          new BridgedStringMap(remoteConfig)
              .guardedMap(
                  map ->
                      Native.ConnectionManager_new(env.value, userAgent, map, buildVariant.value)));
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

    private void setRemoteConfig(Map<String, String> remoteConfig, BuildVariant buildVariant) {
      new BridgedStringMap(remoteConfig)
          .guardedRun(
              map ->
                  this.guardedRun(
                      h -> Native.ConnectionManager_set_remote_config(h, map, buildVariant.value)));
    }

    @Override
    public long getConnectionManagerUnsafeNativeHandle() {
      return unsafeNativeHandleWithoutGuard();
    }

    @Override
    protected void release(final long nativeHandle) {
      Native.ConnectionManager_Destroy(nativeHandle);
    }
  }
}
