//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.FilterExceptions;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

public interface ChatConnectionListener {
  /**
   * Called when the server delivers an incoming message to the client.
   *
   * <p>{@param serverDeliveryTimestamp} is in milliseconds.
   *
   * <p>If {@param sendAck}'s {@code send} method is not called, the server will leave this message
   * in the message queue and attempt to deliver it again in the future.
   */
  void onIncomingMessage(
      ChatConnection chat, byte[] envelope, long serverDeliveryTimestamp, ServerMessageAck sendAck);

  /**
   * Called when the server indicates that there are no further messages in the message queue.
   *
   * <p>Note that further messages may still be delivered; this merely indicates that all messages
   * that were in the queue when the websocket was first connected have been delivered.
   *
   * <p>The default implementation of this method does nothing.
   */
  default void onQueueEmpty(ChatConnection chat) {}

  /**
   * Called when the client gets disconnected from the server.
   *
   * <p>This includes both deliberate disconnects as well as unexpected socket closures. In the case
   * of the former, the {@param disconnectReason} will be null.
   *
   * <p>The default implementation of this method does nothing.
   */
  default void onConnectionInterrupted(
      ChatConnection chat, ChatServiceException disconnectReason) {}

  public static class ServerMessageAck extends NativeHandleGuard.SimpleOwner {
    private final TokioAsyncContext asyncContext;

    ServerMessageAck(TokioAsyncContext context, long nativeHandle) {
      super(nativeHandle);
      asyncContext = context;
    }

    protected void release(long nativeHandle) {
      Native.ServerMessageAck_Destroy(nativeHandle);
    }

    /**
     * Responds to the server, confirming delivery of an incoming message.
     *
     * <p>If the connection on which the message was delivered has already been closed, the Future
     * will fail. However, there's not much that can be done in this scenario besides perhaps
     * logging the error. Since the message was not ack'd, the server will attempt to deliver it
     * again later.
     *
     * @throws ChatServiceInactiveException if the connection is already terminated.
     * @throws ChatServiceException if the send fails for another reason.
     */
    public void send() throws ChatServiceInactiveException, ChatServiceException {
      FilterExceptions.filterExceptions(
          ChatServiceInactiveException.class,
          ChatServiceException.class,
          () -> {
            guardedRunChecked(Native::ServerMessageAck_Send);
          });
    }
  }
}
