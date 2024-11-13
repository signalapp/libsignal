//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.net.internal.BridgeChatListener;

/**
 * Represents an unauthenticated (i.e. hopefully anonymous) communication channel with the
 * ChatService.
 *
 * <p>Created by the factory method Network.createUnauthChatService() rather than instantiated
 * directly.
 */
public class UnauthenticatedChatService extends ChatService {
  final Network.Environment environment;
  private final KeyTransparencyClient keyTransparencyClient;

  UnauthenticatedChatService(
      final TokioAsyncContext tokioAsyncContext,
      final Network.ConnectionManager connectionManager,
      ChatListener listener) {
    super(tokioAsyncContext, connectionManager, Native::ChatService_new_unauth, listener);
    this.environment = connectionManager.environment();
    this.keyTransparencyClient = new KeyTransparencyClient(this, tokioAsyncContext);
  }

  /**
   * High-level key transparency subsystem client on top using {@code this} to communicate with the
   * chat server.
   *
   * @return an instance of {@link KeyTransparencyClient}
   */
  public KeyTransparencyClient keyTransparencyClient() {
    return this.keyTransparencyClient;
  }

  // Implementing these abstract methods from ChatService allows UnauthenticatedChatService
  //   to get the implementation of its main functionality (connect, send, etc.)
  //   using the shared implementations of those methods in ChatService.
  @Override
  protected CompletableFuture disconnectWrapper(
      long nativeAsyncContextHandle, long nativeChatServiceHandle) {
    return Native.ChatService_disconnect_unauth(nativeAsyncContextHandle, nativeChatServiceHandle);
  }

  @Override
  protected CompletableFuture<Object> sendWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      long nativeRequestHandle,
      int timeoutMillis) {
    return Native.ChatService_unauth_send(
        nativeAsyncContextHandle, nativeChatServiceHandle, nativeRequestHandle, timeoutMillis);
  }

  @Override
  protected CompletableFuture<Object> connectWrapper(
      long nativeAsyncContextHandle, long nativeChatServiceHandle) {
    return Native.ChatService_connect_unauth(nativeAsyncContextHandle, nativeChatServiceHandle);
  }

  @Override
  protected CompletableFuture<Object> sendAndDebugWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      long nativeRequestHandle,
      int timeoutMillis) {
    return Native.ChatService_unauth_send_and_debug(
        nativeAsyncContextHandle, nativeChatServiceHandle, nativeRequestHandle, timeoutMillis);
  }

  @Override
  protected void release(long nativeChatServiceHandle) {
    Native.UnauthChat_Destroy(nativeChatServiceHandle);
  }

  @Override
  protected void setListenerWrapper(
      long nativeAsyncContextHandle,
      long nativeChatServiceHandle,
      BridgeChatListener bridgeChatListener) {
    Native.ChatService_SetListenerUnauth(
        nativeAsyncContextHandle, nativeChatServiceHandle, bridgeChatListener);
  }
}
