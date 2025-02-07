//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.lang.ref.WeakReference;
import java.net.MalformedURLException;
import java.util.Map;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.FilterExceptions;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.net.internal.BridgeChatListener;

/**
 * Represents an established connection to the Chat Service.
 *
 * <p>When a new {@code ChatConnection} is created, it is connected but not yet active. The
 * registered listener will not receive any events until {@link #start()} is called.
 */
public abstract class ChatConnection extends NativeHandleGuard.SimpleOwner {
  private final TokioAsyncContext tokioAsyncContext;
  private final ChatConnectionListener chatListener;

  protected ChatConnection(
      final TokioAsyncContext tokioAsyncContext,
      final long nativeHandle,
      final ChatConnectionListener chatListener) {
    super(nativeHandle);
    this.tokioAsyncContext = tokioAsyncContext;
    this.chatListener = chatListener;
  }

  protected static class ListenerBridge implements BridgeChatListener {
    // Stored as a weak reference because otherwise we'll have a reference cycle:
    // - After setting a listener, Rust has a GC GlobalRef to this ListenerBridge
    // - This field is a normal Java reference to the ChatConnection
    // - ChatConnection owns the Rust ChatConnection object
    protected WeakReference<ChatConnection> chat;

    protected ListenerBridge(ChatConnection chat) {
      this.chat = new WeakReference<>(chat);
    }

    public void onIncomingMessage(
        byte[] envelope, long serverDeliveryTimestamp, long sendAckHandle) {

      ChatConnection chat = this.chat.get();
      if (chat == null) return;
      if (chat.chatListener == null) return;

      chat.chatListener.onIncomingMessage(
          chat,
          envelope,
          serverDeliveryTimestamp,
          new ChatConnectionListener.ServerMessageAck(chat.tokioAsyncContext, sendAckHandle));
    }

    public void onQueueEmpty() {
      ChatConnection chat = this.chat.get();
      if (chat == null) return;
      if (chat.chatListener == null) return;

      chat.chatListener.onQueueEmpty(chat);
    }

    public void onConnectionInterrupted(Throwable disconnectReason) {
      ChatConnection chat = this.chat.get();
      if (chat == null) return;
      if (chat.chatListener == null) return;

      ChatServiceException disconnectReasonChatServiceException =
          (disconnectReason == null)
              ? null
              : (disconnectReason instanceof ChatServiceException)
                  ? (ChatServiceException) disconnectReason
                  : new ChatServiceException("OtherDisconnectReason", disconnectReason);
      chat.chatListener.onConnectionInterrupted(chat, disconnectReasonChatServiceException);
    }
  }

  /**
   * Starts a created, but not yet active, chat connection.
   *
   * <p>This must be called on a new {@code ChatConnection} before it can start receiving incoming
   * messages from the server. It is an error to call this method more than once on a {@code
   * ChatConnection}.
   */
  public void start() {
    ListenerBridge bridgedChatListener = new ListenerBridge(this);
    this.guardedRun(
        nativeChatConnectionHandle ->
            this.startWrapper(nativeChatConnectionHandle, bridgedChatListener));
  }

  /**
   * Initiates termination of the underlying connection to the Chat Service. After the service is
   * disconnected, it cannot be reconnected.
   *
   * @return a future that completes when the underlying connection is terminated.
   */
  @SuppressWarnings("unchecked")
  public CompletableFuture<Void> disconnect() {
    return tokioAsyncContext.guardedMap(
        asyncContextHandle ->
            guardedMap(
                chatConnectionHandle ->
                    disconnectWrapper(asyncContextHandle, chatConnectionHandle)));
  }

  /**
   * Sends request to the Chat Service over this channel.
   *
   * @param req request object
   * @return a {@code CompletableFuture} of a {@link Response}.
   * @throws MalformedURLException if {@code pathAndQuery} component of the request has an invalid
   *     structure.
   * @throws RuntimeException if {@link #start()} has not been called first.
   */
  public CompletableFuture<Response> send(final Request req) throws MalformedURLException {
    final InternalRequest internalRequest = buildInternalRequest(req);
    try (final NativeHandleGuard asyncContextHandle = new NativeHandleGuard(tokioAsyncContext);
        final NativeHandleGuard chatConnectionHandle = new NativeHandleGuard(this);
        final NativeHandleGuard requestHandle = new NativeHandleGuard(internalRequest)) {
      return sendWrapper(
              asyncContextHandle.nativeHandle(),
              chatConnectionHandle.nativeHandle(),
              requestHandle.nativeHandle(),
              req.timeoutMillis)
          .thenApply(o -> (Response) o);
    }
  }

  // These are meant to be thin wrappers around the correct call to Native.ChatConnection_* calls
  //   for each of the concrete implementing classes.
  protected abstract CompletableFuture disconnectWrapper(
      long nativeAsyncContextHandle, long nativeChatConnectionHandle);

  protected abstract CompletableFuture<Object> sendWrapper(
      long nativeAsyncContextHandle,
      long nativeChatConnectionHandle,
      long nativeRequestHandle,
      int timeoutMillis);

  protected abstract void startWrapper(
      long nativeChatConnectionHandle, BridgeChatListener listener);

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

    InternalRequest(long handle) {
      super(handle);
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
}
