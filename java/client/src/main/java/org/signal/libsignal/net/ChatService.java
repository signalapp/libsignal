//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.util.Map;
import java.util.function.Function;
import org.signal.libsignal.internal.CalledFromNative;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.FilterExceptions;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.net.internal.BridgeChatListener;

/** Represents an API of communication with the Chat Service. */
public abstract class ChatService extends NativeHandleGuard.SimpleOwner {
  private final TokioAsyncContext tokioAsyncContext;
  protected final ChatListener chatListener;

  ChatService(
      final TokioAsyncContext tokioAsyncContext,
      final Network.ConnectionManager connectionManager,
      Function<Long, Long> chatServiceCreateWrapper,
      ChatListener chatListener) {
    super(connectionManager.guardedMap(chatServiceCreateWrapper::apply));
    this.tokioAsyncContext = tokioAsyncContext;
    this.chatListener = chatListener;

    if (chatListener != null) {
      var listenerBridge = new ListenerBridge(this);
      tokioAsyncContext.guardedRun(
          asyncContextHandle ->
              guardedRun(
                  chatServiceHandle ->
                      setListenerWrapper(asyncContextHandle, chatServiceHandle, listenerBridge)));
    }
  }

  private static final class ListenerBridge implements BridgeChatListener {
    // Stored as a weak reference because otherwise we'll have a reference cycle:
    // - After setting a listener, Rust has a GC GlobalRef to this ListenerBridge
    // - This field is a normal Java reference to the ChatService
    // - ChatService owns the Rust ChatService object
    private final WeakReference<ChatService> chat;

    ListenerBridge(ChatService chat) {
      this.chat = new WeakReference<>(chat);
    }

    public void onIncomingMessage(
        byte[] envelope, long serverDeliveryTimestamp, long sendAckHandle) {
      ChatService chat = this.chat.get();
      if (chat == null) return;
      if (chat.chatListener == null) return;

      chat.chatListener.onIncomingMessage(
          chat,
          envelope,
          serverDeliveryTimestamp,
          new ChatListener.ServerMessageAck(chat.tokioAsyncContext, sendAckHandle));
    }

    public void onQueueEmpty() {
      ChatService chat = this.chat.get();
      if (chat == null) return;
      if (chat.chatListener == null) return;

      chat.chatListener.onQueueEmpty(chat);
    }

    public void onConnectionInterrupted(Throwable disconnectReason) {
      ChatService chat = this.chat.get();
      if (chat == null) return;
      if (chat.chatListener == null) return;

      ChatServiceException disconnectReasonChatServiceException =
          (disconnectReason instanceof ChatServiceException)
              ? (ChatServiceException) disconnectReason
              : new ChatServiceException("OtherDisconnectReason", disconnectReason);
      chat.chatListener.onConnectionInterrupted(chat, disconnectReasonChatServiceException);
    }
  }

  /**
   * Initiates termination of the underlying connection to the Chat Service. After the service is
   * disconnected, it will not attempt to automatically reconnect until you call {@link #connect()}.
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
                chatServiceHandle -> disconnectWrapper(asyncContextHandle, chatServiceHandle)));
  }

  /**
   * Initiates establishing of the underlying connection to the Chat Service. Once the service is
   * connected, all the requests will be using the established connection.
   *
   * <p>The resulting future may fail with {@link AppExpiredException}, {@link
   * DeviceDeregisteredException}, or {@link RetryLaterException} (inside an {@link
   * java.util.concurrent.ExecutionException ExecutionException}), along with other {@link
   * ChatServiceException}s.
   *
   * @return a future with the result of the connection attempt (either a {@link DebugInfo} or an
   *     error).
   */
  public CompletableFuture<DebugInfo> connect() {
    return tokioAsyncContext.guardedMap(
        asyncContextHandle ->
            guardedMap(
                chatServiceHandle ->
                    connectWrapper(asyncContextHandle, chatServiceHandle)
                        .thenApply(o -> (DebugInfo) o)));
  }

  /**
   * Sends request to the Chat Service over this channel.
   *
   * @param req request object
   * @return a {@code CompletableFuture} of a {@link Response}. The future will fail with a {@link
   *     ChatServiceInactiveException} (inside an {@link java.util.concurrent.ExecutionException
   *     ExecutionException}) if you haven't called {@link #connect()} }.
   * @throws MalformedURLException if {@code pathAndQuery} component of the request has an invalid
   *     structure.
   */
  public CompletableFuture<Response> send(final Request req) throws MalformedURLException {
    final InternalRequest internalRequest = buildInternalRequest(req);
    try (final NativeHandleGuard asyncContextHandle = new NativeHandleGuard(tokioAsyncContext);
        final NativeHandleGuard chatServiceHandle = new NativeHandleGuard(this);
        final NativeHandleGuard requestHandle = new NativeHandleGuard(internalRequest)) {
      return sendWrapper(
              asyncContextHandle.nativeHandle(),
              chatServiceHandle.nativeHandle(),
              requestHandle.nativeHandle(),
              req.timeoutMillis)
          .thenApply(o -> (Response) o);
    }
  }

  /**
   * Sends request to the Chat Service over this channel.
   *
   * <p>In addition to the response, an object containing debug information about the request flow
   * is returned.
   *
   * @param req request object
   * @return a {@code CompletableFuture} of a {@link ResponseAndDebugInfo}. The future will fail
   *     with a {@link ChatServiceInactiveException} (inside an {@link
   *     java.util.concurrent.ExecutionException ExecutionException}) if you haven't called {@link
   *     #connect()}.
   * @throws MalformedURLException if {@code pathAndQuery} component of the request has an invalid
   *     structure.
   */
  public CompletableFuture<ResponseAndDebugInfo> sendAndDebug(final Request req)
      throws MalformedURLException {
    final InternalRequest internalRequest = buildInternalRequest(req);
    try (final NativeHandleGuard asyncContextHandle = new NativeHandleGuard(tokioAsyncContext);
        final NativeHandleGuard chatServiceHandle = new NativeHandleGuard(this);
        final NativeHandleGuard requestHandle = new NativeHandleGuard(internalRequest)) {
      return sendAndDebugWrapper(
              asyncContextHandle.nativeHandle(),
              chatServiceHandle.nativeHandle(),
              requestHandle.nativeHandle(),
              req.timeoutMillis)
          .thenApply(o -> (ResponseAndDebugInfo) o);
    }
  }

  // These are meant to be thin wrappers around the correct call to Native.ChatService_* calls
  //   for each of the concrete implementing classes.
  protected abstract CompletableFuture disconnectWrapper(
      long nativeAsyncContextHandle, long nativeChatServiceHandle);

  protected abstract CompletableFuture<Object> sendWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      long nativeRequestHandle,
      int timeoutMillis);

  protected abstract CompletableFuture<Object> connectWrapper(
      long nativeAsyncContextHandle, long nativeChatServiceHandle);

  protected abstract CompletableFuture<Object> sendAndDebugWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      long nativeRequestHandle,
      int timeoutMillis);

  protected abstract void setListenerWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      BridgeChatListener bridgeChatListener);

  static InternalRequest buildInternalRequest(final Request req) throws MalformedURLException {
    final InternalRequest result =
        new InternalRequest(req.method(), req.pathAndQuery(), req.body());
    req.headers().forEach(result::addHeader);
    return result;
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
