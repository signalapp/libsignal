//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.util.Locale;
import kotlin.Pair;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.net.internal.BridgeChatListener;

/**
 * Represents an authenticated communication channel with the ChatConnection.
 *
 * <p>Created by the factory method {@link Network#connectAuthChat} rather than instantiated
 * directly.
 *
 * <p>Note that a newly-created instance of this class won't be usable for sending messages or
 * receiving events until {@link ChatConnection#start()} is called.
 */
public class AuthenticatedChatConnection extends ChatConnection {
  private AuthenticatedChatConnection(
      final TokioAsyncContext tokioAsyncContext,
      long nativeHandle,
      ChatConnectionListener listener) {
    super(tokioAsyncContext, nativeHandle, listener);
  }

  static CompletableFuture<AuthenticatedChatConnection> connect(
      final TokioAsyncContext tokioAsyncContext,
      final Network.ConnectionManager connectionManager,
      final String username,
      final String password,
      final boolean receiveStories,
      final Locale locale,
      ChatConnectionListener chatListener) {
    return tokioAsyncContext.guardedMap(
        asyncContextHandle ->
            connectionManager.guardedMap(
                connectionManagerHandle ->
                    Native.AuthenticatedChatConnection_connect(
                            asyncContextHandle,
                            connectionManagerHandle,
                            username,
                            password,
                            receiveStories,
                            Network.languageCodesForLocale(locale))
                        .makeCancelable(tokioAsyncContext)
                        .thenApply(
                            nativeHandle ->
                                new AuthenticatedChatConnection(
                                    tokioAsyncContext, nativeHandle, chatListener))));
  }

  /**
   * Test-only method to create a {@code AuthenticatedChatConnection} connected to a fake remote.
   *
   * <p>The returned {@link FakeChatRemote} can be used to send messages to the connection.
   */
  public static Pair<AuthenticatedChatConnection, FakeChatRemote> fakeConnect(
      final TokioAsyncContext tokioAsyncContext, ChatConnectionListener listener) {
    return fakeConnect(tokioAsyncContext, listener, new String[0]);
  }

  /**
   * Test-only method to create a {@code AuthenticatedChatConnection} connected to a fake remote.
   *
   * <p>The returned {@link FakeChatRemote} can be used to send messages to the connection.
   */
  public static Pair<AuthenticatedChatConnection, FakeChatRemote> fakeConnect(
      final TokioAsyncContext tokioAsyncContext, ChatConnectionListener listener, String[] alerts) {

    return tokioAsyncContext.guardedMap(
        asyncContextHandle -> {
          SetChatLaterListenerBridge bridgeListener = new SetChatLaterListenerBridge();
          long fakeChatConnection =
              NativeTesting.TESTING_FakeChatConnection_Create(
                  asyncContextHandle, bridgeListener, String.join("\n", alerts));
          AuthenticatedChatConnection chat =
              new AuthenticatedChatConnection(
                  tokioAsyncContext,
                  NativeTesting.TESTING_FakeChatConnection_TakeAuthenticatedChat(
                      fakeChatConnection),
                  listener);
          bridgeListener.setChat(chat);
          FakeChatRemote fakeRemote =
              new FakeChatRemote(
                  tokioAsyncContext,
                  NativeTesting.TESTING_FakeChatConnection_TakeRemote(fakeChatConnection));
          NativeTesting.FakeChatConnection_Destroy(fakeChatConnection);
          return new Pair<>(chat, fakeRemote);
        });
  }

  // Implementing these abstract methods from ChatConnection allows AuthenticatedChatConnection
  //   to get the implementation of its main functionality (connect, send, etc.)
  //   using the shared implementations of those methods in ChatConnection.
  @Override
  protected CompletableFuture disconnectWrapper(
      long nativeAsyncContextHandle, long nativeChatConnectionHandle) {
    return Native.AuthenticatedChatConnection_disconnect(
        nativeAsyncContextHandle, nativeChatConnectionHandle);
  }

  @Override
  protected void startWrapper(long nativeChatConnectionHandle, BridgeChatListener listener) {
    Native.AuthenticatedChatConnection_init_listener(nativeChatConnectionHandle, listener);
  }

  @Override
  protected CompletableFuture<Object> sendWrapper(
      long nativeAsyncContextHandle,
      long nativeChatConnectionHandle,
      long nativeRequestHandle,
      int timeoutMillis) {
    return Native.AuthenticatedChatConnection_send(
        nativeAsyncContextHandle, nativeChatConnectionHandle, nativeRequestHandle, timeoutMillis);
  }

  @Override
  protected void release(long nativeChatConnectionHandle) {
    Native.AuthenticatedChatConnection_Destroy(nativeChatConnectionHandle);
  }
}
