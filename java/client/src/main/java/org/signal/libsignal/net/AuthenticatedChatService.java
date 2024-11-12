//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.net.internal.BridgeChatListener;

/**
 * Represents an authenticated communication channel with the ChatService.
 *
 * <p>Created by the factory method Network.createAuthChatService() rather than instantiated
 * directly.
 */
public class AuthenticatedChatService extends ChatService {
  AuthenticatedChatService(
      final TokioAsyncContext tokioAsyncContext,
      final Network.ConnectionManager connectionManager,
      final String username,
      final String password,
      final boolean receiveStories,
      ChatListener chatListener) {
    super(
        tokioAsyncContext,
        connectionManager,
        (connectionManagerHandle) ->
            Native.ChatService_new_auth(
                connectionManagerHandle, username, password, receiveStories),
        chatListener);
  }

  // Implementing these abstract methods from ChatService allows UnauthenticatedChatService
  //   to get the implementation of its main functionality (connect, send, etc.)
  //   using the shared implementations of those methods in ChatService.
  @Override
  protected CompletableFuture disconnectWrapper(
      long nativeAsyncContextHandle, long nativeChatServiceHandle) {
    return Native.ChatService_disconnect_auth(nativeAsyncContextHandle, nativeChatServiceHandle);
  }

  @Override
  protected CompletableFuture<Object> sendWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      long nativeRequestHandle,
      int timeoutMillis) {
    return Native.ChatService_auth_send(
        nativeAsyncContextHandle, nativeChatServiceHandle, nativeRequestHandle, timeoutMillis);
  }

  @Override
  protected CompletableFuture<Object> connectWrapper(
      long nativeAsyncContextHandle, long nativeChatServiceHandle) {
    return Native.ChatService_connect_auth(nativeAsyncContextHandle, nativeChatServiceHandle);
  }

  @Override
  protected CompletableFuture<Object> sendAndDebugWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      long nativeRequestHandle,
      int timeoutMillis) {
    return Native.ChatService_auth_send_and_debug(
        nativeAsyncContextHandle, nativeChatServiceHandle, nativeRequestHandle, timeoutMillis);
  }

  @Override
  protected void release(long nativeChatServiceHandle) {
    Native.AuthChat_Destroy(nativeChatServiceHandle);
  }

  @Override
  protected void setListenerWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      BridgeChatListener bridgeChatListener) {
    Native.ChatService_SetListenerAuth(
        nativeAsyncContextHandle, nativeChatServiceHandle, bridgeChatListener);
  }
}
