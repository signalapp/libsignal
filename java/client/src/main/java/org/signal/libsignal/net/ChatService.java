//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.net.MalformedURLException;
import java.util.Map;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.FilterExceptions;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * Represents an API of communication with the Chat Service.
 *
 * <p>An instance of this object is obtained via call to {@link Network#createChatService(String,
 * String, boolean)} method.
 */
public class ChatService extends NativeHandleGuard.SimpleOwner {

  private final TokioAsyncContext tokioAsyncContext;

  ChatService(
      final TokioAsyncContext tokioAsyncContext,
      final Network.ConnectionManager connectionManager,
      final String username,
      final String password,
      final boolean receiveStories) {
    // For now, ignore anything to do with authenticated connections.
    super(
        connectionManager.guardedMap(
            connectionManagerHandle -> Native.ChatService_new_unauth(connectionManagerHandle)));
    this.tokioAsyncContext = tokioAsyncContext;
  }

  /**
   * Initiates termination of the underlying connection to the Chat Service. After the service is
   * disconnected, it will not attempt to automatically reconnect until you call {@link
   * #connectAuthenticated()} and/or {@link #connectUnauthenticated()}.
   *
   * <p>Note: the same instance of {@code ChatService} can be reused after {@code disconnect()} was
   * called.
   *
   * @return a future that completes when the underlying connection is terminated.
   */
  @SuppressWarnings("unchecked")
  public CompletableFuture<Void> disconnect() {
    return tokioAsyncContext.guardedMap(
        asyncContextHandle ->
            guardedMap(
                chatServiceHandle ->
                    Native.ChatService_disconnect_unauth(asyncContextHandle, chatServiceHandle)));
  }

  /**
   * Initiates establishing of the underlying authenticated connection to the Chat Service. Once the
   * service is connected, all the requests will be using the established connection. Also, if the
   * connection is lost for any reason other than the call to {@link #disconnect()}, an automatic
   * reconnect attempt will be made.
   *
   * <p>Calling this method will result in starting to accept incoming requests from the Chat
   * Service.
   *
   * <p>The resulting future may fail with {@link AppExpiredException} or {@link
   * DeviceDeregisteredException} (inside an {@link java.util.concurrent.ExecutionException
   * ExecutionException}), along with other {@link ChatServiceException}s.
   *
   * @return a future with the result of the connection attempt (either a {@link DebugInfo} or an
   *     error).
   */
  public CompletableFuture<DebugInfo> connectAuthenticated() {
    throw new UnsupportedOperationException("not yet implemented on Android");
  }

  /**
   * Initiates establishing of the underlying unauthenticated connection to the Chat Service. Once
   * the service is connected, all the requests will be using the established connection. Also, if
   * the connection is lost for any reason other than the call to {@link #disconnect()}, an
   * automatic reconnect attempt will be made.
   *
   * <p>The resulting future may fail with {@link AppExpiredException} (inside an {@link
   * java.util.concurrent.ExecutionException ExecutionException}), along with other {@link
   * ChatServiceException}s.
   *
   * @return a future with the result of the connection attempt (either a {@link DebugInfo} or an
   *     error).
   */
  public CompletableFuture<DebugInfo> connectUnauthenticated() {
    return tokioAsyncContext.guardedMap(
        asyncContextHandle ->
            guardedMap(
                chatServiceHandle ->
                    Native.ChatService_connect_unauth(asyncContextHandle, chatServiceHandle)
                        .thenApply(o -> (DebugInfo) o)));
  }

  /**
   * Sends request to the Chat Service over an unauthenticated channel.
   *
   * @param req request object
   * @return a {@code CompletableFuture} of a {@link Response}. The future will fail with a {@link
   *     ChatServiceInactiveException} (inside an {@link java.util.concurrent.ExecutionException
   *     ExecutionException}) if you haven't called {@link #connectUnauthenticated()}.
   * @throws MalformedURLException if {@code pathAndQuery} component of the request has an invalid
   *     structure.
   */
  public CompletableFuture<Response> unauthenticatedSend(final Request req)
      throws MalformedURLException {
    final InternalRequest internalRequest = buildInternalRequest(req);
    try (final NativeHandleGuard asyncContextHandle = new NativeHandleGuard(tokioAsyncContext);
        final NativeHandleGuard chatServiceHandle = new NativeHandleGuard(this);
        final NativeHandleGuard requestHandle = new NativeHandleGuard(internalRequest)) {
      return Native.ChatService_unauth_send(
              asyncContextHandle.nativeHandle(),
              chatServiceHandle.nativeHandle(),
              requestHandle.nativeHandle(),
              req.timeoutMillis)
          .thenApply(o -> (Response) o);
    }
  }

  /**
   * Sends request to the Chat Service over an unauthenticated channel.
   *
   * <p>In addition to the response, an object containing debug information about the request flow
   * is returned.
   *
   * @param req request object
   * @return a {@code CompletableFuture} of a {@link ResponseAndDebugInfo}. The future will fail
   *     with a {@link ChatServiceInactiveException} (inside an {@link
   *     java.util.concurrent.ExecutionException ExecutionException}) if you haven't called {@link
   *     #connectUnauthenticated()}.
   * @throws MalformedURLException if {@code pathAndQuery} component of the request has an invalid
   *     structure.
   */
  public CompletableFuture<ResponseAndDebugInfo> unauthenticatedSendAndDebug(final Request req)
      throws MalformedURLException {
    final InternalRequest internalRequest = buildInternalRequest(req);
    try (final NativeHandleGuard asyncContextHandle = new NativeHandleGuard(tokioAsyncContext);
        final NativeHandleGuard chatServiceHandle = new NativeHandleGuard(this);
        final NativeHandleGuard requestHandle = new NativeHandleGuard(internalRequest)) {
      return Native.ChatService_unauth_send_and_debug(
              asyncContextHandle.nativeHandle(),
              chatServiceHandle.nativeHandle(),
              requestHandle.nativeHandle(),
              req.timeoutMillis)
          .thenApply(o -> (ResponseAndDebugInfo) o);
    }
  }

  /**
   * Sends request to the Chat Service over an authenticated channel.
   *
   * @param req request object
   * @return a {@code CompletableFuture} of a {@link Response}. The future will fail with a {@link
   *     ChatServiceInactiveException} (inside an {@link java.util.concurrent.ExecutionException
   *     ExecutionException}) if you haven't called {@link #connectAuthenticated()}.
   * @throws MalformedURLException if {@code pathAndQuery} component of the request has an invalid
   *     structure.
   */
  public CompletableFuture<Response> authenticatedSend(final Request req)
      throws MalformedURLException {
    throw new UnsupportedOperationException("not yet implemented on Android");
  }

  /**
   * Sends request to the Chat Service over an authenticated channel.
   *
   * <p>In addition to the response, an object containing debug information about the request flow
   * is returned.
   *
   * @param req request object
   * @return a {@code CompletableFuture} of a {@link ResponseAndDebugInfo}. The future will fail
   *     with a {@link ChatServiceInactiveException} (inside an {@link
   *     java.util.concurrent.ExecutionException ExecutionException}) if you haven't called {@link
   *     #connectAuthenticated()}.
   * @throws MalformedURLException if {@code pathAndQuery} component of the request has an invalid
   *     structure.
   * @throws ChatServiceInactiveException if you haven't called {@link #connectAuthenticated()}.
   */
  public CompletableFuture<ResponseAndDebugInfo> authenticatedSendAndDebug(final Request req)
      throws MalformedURLException {
    throw new UnsupportedOperationException("not yet implemented on Android");
  }

  static InternalRequest buildInternalRequest(final Request req) throws MalformedURLException {
    final InternalRequest result =
        new InternalRequest(req.method(), req.pathAndQuery(), req.body());
    req.headers().forEach(result::addHeader);
    return result;
  }

  @Override
  protected void release(final long nativeHandle) {
    Native.UnauthChat_Destroy(nativeHandle);
  }

  static class InternalRequest extends NativeHandleGuard.SimpleOwner {
    InternalRequest(final String method, final String pathAndQuery, final byte[] body)
        throws MalformedURLException {
      super(
          FilterExceptions.filterExceptions(
              MalformedURLException.class,
              () -> Native.HttpRequest_new(method, pathAndQuery, body)));
    }

    @Override
    protected void release(final long nativeHandle) {
      Native.HttpRequest_Destroy(nativeHandle);
    }

    public void addHeader(final String name, final String value) {
      guardedRun(h -> Native.HttpRequest_add_header(h, name, value));
    }
  }

  public record Request(
      String method,
      String pathAndQuery,
      Map<String, String> headers,
      byte[] body,
      int timeoutMillis) {}

  public record Response(int status, String message, Map<String, String> headers, byte[] body) {}

  public record DebugInfo(IpType ipType, int durationMs, String connectionInfo) {
    @CalledFromNative
    DebugInfo(byte ipTypeCode, int durationMs, String connectionInfo) {
      this(IpType.values()[ipTypeCode], durationMs, connectionInfo);
    }
  }

  public record ResponseAndDebugInfo(Response response, DebugInfo debugInfo) {}
}
