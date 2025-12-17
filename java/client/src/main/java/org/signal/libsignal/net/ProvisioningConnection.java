//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.lang.ref.WeakReference;
import kotlin.Pair;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.internal.TokioAsyncContext;
import org.signal.libsignal.net.internal.BridgeProvisioningListener;

/**
 * A chat connection used specifically for provisioning linked devices.
 *
 * <p>Note that no messages are sent *from* the client for a provisioning connection; all the
 * interesting functionality is in the events delivered to the {@link
 * ProvisioningConnectionListener}.
 */
public class ProvisioningConnection extends NativeHandleGuard.SimpleOwner {
  private final TokioAsyncContext tokioAsyncContext;
  private final ProvisioningConnectionListener listener;

  protected ProvisioningConnection(
      final TokioAsyncContext tokioAsyncContext,
      final long nativeHandle,
      final ProvisioningConnectionListener listener) {
    super(nativeHandle);
    this.tokioAsyncContext = tokioAsyncContext;
    this.listener = listener;
  }

  static CompletableFuture<ProvisioningConnection> connect(
      final TokioAsyncContext tokioAsyncContext,
      final Network.ConnectionManager connectionManager,
      final ProvisioningConnectionListener listener) {
    return tokioAsyncContext.guardedMap(
        asyncContextHandle ->
            connectionManager.guardedMap(
                connectionManagerHandle ->
                    Native.ProvisioningChatConnection_connect(
                            asyncContextHandle, connectionManagerHandle)
                        .makeCancelable(tokioAsyncContext)
                        .thenApply(
                            nativeHandle ->
                                new ProvisioningConnection(
                                    tokioAsyncContext, nativeHandle, listener))));
  }

  protected static class ListenerBridge implements BridgeProvisioningListener {
    // Stored as a weak reference because otherwise we'll have a reference cycle:
    // - After setting a listener, Rust has a GC GlobalRef to this ListenerBridge
    // - This field is a normal Java reference to the ProvisioningConnection
    // - ProvisioningConnection owns the Rust ProvisioningConnection object
    protected WeakReference<ProvisioningConnection> connection;

    protected ListenerBridge(ProvisioningConnection connection) {
      this.connection = new WeakReference<>(connection);
    }

    public void receivedAddress(String address, long sendAckHandle) {
      var ack = new ChatConnectionListener.ServerMessageAck(sendAckHandle);
      ProvisioningConnection connection = this.connection.get();
      if (connection == null) return;
      if (connection.listener == null) return;

      connection.listener.onReceivedAddress(connection, address, ack);
    }

    public void receivedEnvelope(byte[] envelope, long sendAckHandle) {
      var ack = new ChatConnectionListener.ServerMessageAck(sendAckHandle);
      ProvisioningConnection connection = this.connection.get();
      if (connection == null) return;
      if (connection.listener == null) return;

      connection.listener.onReceivedEnvelope(connection, envelope, ack);
    }

    public void connectionInterrupted(Throwable disconnectReason) {
      ProvisioningConnection connection = this.connection.get();
      if (connection == null) return;
      if (connection.listener == null) return;

      ChatServiceException disconnectReasonChatServiceException =
          (disconnectReason == null)
              ? null
              : (disconnectReason instanceof ChatServiceException)
                  ? (ChatServiceException) disconnectReason
                  : new ChatServiceException("OtherDisconnectReason", disconnectReason);
      connection.listener.onConnectionInterrupted(connection, disconnectReasonChatServiceException);
    }
  }

  protected static final class SetChatLaterListenerBridge extends ListenerBridge {
    SetChatLaterListenerBridge() {
      super(null);
    }

    void setChat(ProvisioningConnection connection) {
      this.connection = new WeakReference<>(connection);
    }
  }

  /**
   * Test-only method to create a {@code ProvisioningConnection} connected to a fake remote.
   *
   * <p>The returned {@link FakeChatRemote} can be used to send messages to the connection.
   */
  public static Pair<ProvisioningConnection, FakeChatRemote> fakeConnect(
      final TokioAsyncContext tokioAsyncContext, ProvisioningConnectionListener listener) {

    return tokioAsyncContext.guardedMap(
        asyncContextHandle -> {
          SetChatLaterListenerBridge bridgeListener = new SetChatLaterListenerBridge();
          long fakeChatConnection =
              NativeTesting.TESTING_FakeChatConnection_CreateProvisioning(
                  asyncContextHandle, bridgeListener);
          ProvisioningConnection chat =
              new ProvisioningConnection(
                  tokioAsyncContext,
                  NativeTesting.TESTING_FakeChatConnection_TakeProvisioningChat(fakeChatConnection),
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

  /**
   * Starts a created, but not yet active, provisioning connection.
   *
   * <p>This must be called on a new {@code ProvisioningConnection} before it can start receiving
   * incoming messages from the server. It is an error to call this method more than once on a
   * {@code ProvisioningConnection}.
   */
  public void start() {
    ListenerBridge bridgedListener = new ListenerBridge(this);
    this.guardedRun(
        nativeChatConnectionHandle ->
            Native.ProvisioningChatConnection_init_listener(
                nativeChatConnectionHandle, bridgedListener));
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
                    Native.ProvisioningChatConnection_disconnect(
                        asyncContextHandle, chatConnectionHandle)));
  }

  @Override
  protected void release(long nativeChatConnectionHandle) {
    Native.ProvisioningChatConnection_Destroy(nativeChatConnectionHandle);
  }
}
