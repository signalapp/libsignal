//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.junit.rules.Timeout;
import org.signal.libsignal.internal.CompletableFuture;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.protocol.util.Pair;
import org.signal.libsignal.util.Base64;
import org.signal.libsignal.util.TestEnvironment;

public class ChatServiceTest {

  private static final String USER_AGENT = "test";

  private static final int EXPECTED_STATUS = 200;

  private static final String EXPECTED_MESSAGE = "OK";

  private static final byte[] EXPECTED_CONTENT = "content".getBytes(StandardCharsets.UTF_8);

  private static final Map<String, String> EXPECTED_HEADERS =
      Map.of(
          "content-type", "application/octet-stream",
          "forwarded", "1.1.1.1");

  @Test
  public void testConvertResponse() throws Exception {
    // empty body
    final ChatConnection.Response response1 =
        (ChatConnection.Response) NativeTesting.TESTING_ChatResponseConvert(false);
    assertEquals(EXPECTED_STATUS, response1.status());
    assertEquals(EXPECTED_MESSAGE, response1.message());
    assertArrayEquals(new byte[0], response1.body());
    assertEquals(EXPECTED_HEADERS, response1.headers());

    final ChatConnection.Response response2 =
        (ChatConnection.Response) NativeTesting.TESTING_ChatResponseConvert(true);
    assertEquals(EXPECTED_STATUS, response2.status());
    assertEquals(EXPECTED_MESSAGE, response2.message());
    assertArrayEquals(EXPECTED_CONTENT, response2.body());
    assertEquals(EXPECTED_HEADERS, response2.headers());
  }

  @Test
  public void chatServiceErrorConvert() {
    assertChatServiceErrorIs("AppExpired", AppExpiredException.class);
    assertChatServiceErrorIs("DeviceDeregistered", DeviceDeregisteredException.class);
    assertChatServiceErrorIs("Disconnected", ChatServiceInactiveException.class);

    assertChatServiceErrorIs("WebSocket", ChatServiceException.class);
    assertChatServiceErrorIs("UnexpectedFrameReceived", ChatServiceException.class);
    assertChatServiceErrorIs("ServerRequestMissingId", ChatServiceException.class);
    assertChatServiceErrorIs("IncomingDataInvalid", ChatServiceException.class);
    assertChatServiceErrorIs("RequestSendTimedOut", ChatServiceException.class);
    assertChatServiceErrorIs("TimeoutEstablishingConnection", ChatServiceException.class);
    RetryLaterException retryLater =
        assertChatServiceErrorIs("RetryAfter42Seconds", RetryLaterException.class);
    assertEquals(retryLater.duration, Duration.ofSeconds(42));
    assertChatServiceErrorIs("RequestHasInvalidHeader", ChatServiceException.class);
  }

  private static <E extends Throwable> E assertChatServiceErrorIs(
      String errorDescription, Class<E> expectedErrorType) {
    return assertThrows(
        "for " + errorDescription,
        expectedErrorType,
        () -> NativeTesting.TESTING_ChatServiceErrorConvert(errorDescription));
  }

  @Test
  public void testConstructRequest() throws Exception {
    final String expectedMethod = "GET";
    final String expectedPathAndQuery = "/test";
    final ChatConnection.Request request =
        new ChatConnection.Request(
            expectedMethod, expectedPathAndQuery, EXPECTED_HEADERS, EXPECTED_CONTENT, 5000);
    final ChatConnection.InternalRequest internal = ChatConnection.buildInternalRequest(request);
    assertEquals(expectedMethod, internal.guardedMap(NativeTesting::TESTING_ChatRequestGetMethod));
    assertEquals(
        expectedPathAndQuery, internal.guardedMap(NativeTesting::TESTING_ChatRequestGetPath));
    assertArrayEquals(
        EXPECTED_CONTENT, internal.guardedMap(NativeTesting::TESTING_ChatRequestGetBody));
    EXPECTED_HEADERS.forEach(
        (name, value) ->
            assertEquals(
                value,
                internal.guardedMap(
                    h -> NativeTesting.TESTING_ChatRequestGetHeaderValue(h, name))));
  }

  public static class ConnectTests {
    private static class Listener implements ChatConnectionListener {
      CompletableFuture<ChatServiceException> disconnectReason = new CompletableFuture<>();

      public void onConnectionInterrupted(
          ChatConnection chat, ChatServiceException disconnectReason) {
        this.disconnectReason.complete(disconnectReason);
      }

      public void onIncomingMessage(
          ChatConnection chat,
          byte[] envelope,
          long serverDeliveryTimestamp,
          ChatConnectionListener.ServerMessageAck sendAck) {
        throw new AssertionError("Unexpected incoming message");
      }
    }

    @Rule public Timeout perCaseTimeout = new Timeout(15, TimeUnit.SECONDS);

    @Test
    public void testConnectUnauth() throws Exception {
      // Use the presence of the environment setting to know whether we should
      // make network requests in our tests.
      final String ENABLE_TEST = TestEnvironment.get("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS");
      Assume.assumeNotNull(ENABLE_TEST);

      final Network net = new Network(Network.Environment.STAGING, USER_AGENT);
      final Listener listener = new Listener();
      var chat = net.connectUnauthChat(listener).get();
      chat.start();
      Void disconnectFinished = chat.disconnect().get();

      ChatServiceException disconnectReason = listener.disconnectReason.get();
      assertNull(disconnectReason);
    }

    @Test
    public void testConnectUnauthThroughProxy() throws Exception {
      final String PROXY_SERVER = TestEnvironment.get("LIBSIGNAL_TESTING_PROXY_SERVER");
      Assume.assumeNotNull(PROXY_SERVER);

      // The default TLS proxy config doesn't support staging, so we connect to production.
      final Network net = new Network(Network.Environment.PRODUCTION, USER_AGENT);
      final String[] proxyComponents = PROXY_SERVER.split(":");
      switch (proxyComponents.length) {
        case 1:
          net.setProxy(PROXY_SERVER, 443);
          break;
        case 2:
          net.setProxy(proxyComponents[0], Integer.parseInt(proxyComponents[1]));
          break;
        default:
          throw new IllegalArgumentException("invalid LIBSIGNAL_TESTING_PROXY_SERVER");
      }
      assertEquals(
          (int)
              net.getConnectionManager()
                  .guardedMap(NativeTesting::TESTING_ConnectionManager_isUsingProxy),
          1);

      final Listener listener = new Listener();
      var chat = net.connectUnauthChat(listener).get();
      chat.start();
      Void disconnectFinished = chat.disconnect().get();

      ChatServiceException disconnectReason = listener.disconnectReason.get();
      assertNull(disconnectReason);
    }

    @Test
    public void testConnectUnauthThroughProxyByParts() throws Exception {
      final String PROXY_SERVER = TestEnvironment.get("LIBSIGNAL_TESTING_PROXY_SERVER");
      Assume.assumeNotNull(PROXY_SERVER);

      // The default TLS proxy config doesn't support staging, so we connect to production.
      final Network net = new Network(Network.Environment.PRODUCTION, USER_AGENT);

      String host;
      Integer port;
      final String[] proxyComponents = PROXY_SERVER.split(":");
      switch (proxyComponents.length) {
        case 1:
          host = PROXY_SERVER;
          port = null;
          break;
        case 2:
          host = proxyComponents[0];
          port = Integer.parseInt(proxyComponents[1]);
          break;
        default:
          throw new IllegalArgumentException("invalid LIBSIGNAL_TESTING_PROXY_SERVER");
      }

      String username;
      final String[] hostComponents = host.split("@");
      switch (hostComponents.length) {
        case 1:
          username = null;
          break;
        case 2:
          username = hostComponents[0];
          host = hostComponents[1];
          break;
        default:
          throw new IllegalArgumentException("invalid LIBSIGNAL_TESTING_PROXY_SERVER");
      }

      net.setProxy(Network.SIGNAL_TLS_PROXY_SCHEME, host, port, username, null);
      assertEquals(
          (int)
              net.getConnectionManager()
                  .guardedMap(NativeTesting::TESTING_ConnectionManager_isUsingProxy),
          1);

      final Listener listener = new Listener();
      var chat = net.connectUnauthChat(listener).get();
      chat.start();
      Void disconnectFinished = chat.disconnect().get();

      ChatServiceException disconnectReason = listener.disconnectReason.get();
      assertNull(disconnectReason);
    }
  }

  @Test
  public void testInvalidProxyRejected() throws Exception {
    final Network net = new Network(Network.Environment.PRODUCTION, USER_AGENT);

    final Consumer<ThrowingRunnable> check =
        (callback) -> {
          assertEquals(
              (int)
                  net.getConnectionManager()
                      .guardedMap(NativeTesting::TESTING_ConnectionManager_isUsingProxy),
              0);
          assertThrows(IOException.class, callback);
          assertEquals(
              (int)
                  net.getConnectionManager()
                      .guardedMap(NativeTesting::TESTING_ConnectionManager_isUsingProxy),
              -1);
          net.clearProxy();
        };

    check.accept(() -> net.setProxy("signalfoundation.org", 0));
    check.accept(() -> net.setProxy("signalfoundation.org", 100_000));
    check.accept(() -> net.setProxy("signalfoundation.org", -1));

    check.accept(() -> net.setProxy("socks+shoes", "signalfoundation.org", null, null, null));

    check.accept(
        () -> {
          net.setInvalidProxy();
          throw new IOException("to match all the other test cases");
        });
  }

  private void injectServerRequest(
      AuthenticatedChatConnection.FakeChatRemote fakeRemote, String requestBase64) {
    fakeRemote.guardedRun(
        chatHandle ->
            NativeTesting.TESTING_FakeChatRemoteEnd_SendRawServerRequest(
                chatHandle, Base64.decode(requestBase64)));
  }

  private void injectServerResponse(
      AuthenticatedChatConnection.FakeChatRemote fakeRemote, String requestBase64) {
    fakeRemote.guardedRun(
        chatHandle ->
            NativeTesting.TESTING_FakeChatRemoteEnd_SendRawServerResponse(
                chatHandle, Base64.decode(requestBase64)));
  }

  @Test
  public void testConnectionListenerCallbacks() throws Exception {
    class Listener implements ChatConnectionListener {
      boolean receivedMessage1;
      boolean receivedMessage2;
      boolean receivedQueueEmpty;
      Throwable error;
      CountDownLatch latch = new CountDownLatch(1);

      public void onIncomingMessage(
          ChatConnection chat,
          byte[] envelope,
          long serverDeliveryTimestamp,
          ServerMessageAck sendAck) {
        try {
          switch ((int) serverDeliveryTimestamp) {
            case 1000:
              assertFalse(receivedMessage1);
              assertFalse(receivedMessage2);
              assertFalse(receivedQueueEmpty);
              receivedMessage1 = true;
              break;
            case 2000:
              assertTrue(receivedMessage1);
              assertFalse(receivedMessage2);
              assertFalse(receivedQueueEmpty);
              receivedMessage2 = true;
              break;
            default:
              throw new AssertionError("unexpected message");
          }
        } catch (Throwable error) {
          if (this.error == null) {
            this.error = error;
          }
        }
      }

      public void onQueueEmpty(ChatConnection chat) {
        try {
          assertTrue(receivedMessage1);
          assertTrue(receivedMessage2);
          assertFalse(receivedQueueEmpty);
          receivedQueueEmpty = true;
        } catch (Throwable error) {
          if (this.error == null) {
            this.error = error;
          }
        }
      }

      public void onConnectionInterrupted(
          ChatConnection chat, ChatServiceException disconnectReason) {
        try {
          assertTrue(receivedMessage1);
          assertTrue(receivedMessage2);
          assertTrue(receivedQueueEmpty);
          assertEquals("websocket error: channel already closed", disconnectReason.getMessage());
        } catch (Throwable error) {
          if (this.error == null) {
            this.error = error;
          }
        } finally {
          latch.countDown();
        }
      }
    }

    final TokioAsyncContext tokioAsyncContext = new TokioAsyncContext();
    final Listener listener = new Listener();
    final Pair<AuthenticatedChatConnection, AuthenticatedChatConnection.FakeChatRemote>
        chatAndFakeRemote = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext, listener);
    final AuthenticatedChatConnection chat = chatAndFakeRemote.first();
    final AuthenticatedChatConnection.FakeChatRemote fakeRemote = chatAndFakeRemote.second();

    // The following payloads were generated via protoscope.
    // % protoscope -s | base64
    // The fields are described by chat_websocket.proto in the libsignal-net crate.

    // 1: {"PUT"}
    // 2: {"/api/v1/message"}
    // 3: {1000i64}
    // 5: {"x-signal-timestamp:1000"}
    // 4: 1
    injectServerRequest(
        fakeRemote,
        "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI6AMAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoxMDAwIAE=");
    // 1: {"PUT"}
    // 2: {"/api/v1/message"}
    // 3: {2000i64}
    // 5: {"x-signal-timestamp:2000"}
    // 4: 2
    injectServerRequest(
        fakeRemote,
        "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI0AcAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoyMDAwIAI=");

    // Sending an invalid message should not affect the listener at all, nor should it stop future
    // requests.
    // 1: {"PUT"}
    // 2: {"/invalid"}
    // 4: 10
    injectServerRequest(fakeRemote, "CgNQVVQSCC9pbnZhbGlkIAo=");

    // 1: {"PUT"}
    // 2: {"/api/v1/queue/empty"}
    // 4: 99
    injectServerRequest(fakeRemote, "CgNQVVQSEy9hcGkvdjEvcXVldWUvZW1wdHkgYw==");

    fakeRemote.guardedRun(NativeTesting::TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted);

    listener.latch.await();
    assertNull(listener.error);

    // Make sure the chat object doesn't get GC'd early.
    Native.keepAlive(chat);
  }

  @Test
  public void testSending() throws Exception {
    final TokioAsyncContext tokioAsyncContext = new TokioAsyncContext();
    final Pair<AuthenticatedChatConnection, AuthenticatedChatConnection.FakeChatRemote>
        chatAndFakeRemote = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext, null);
    final AuthenticatedChatConnection chat = chatAndFakeRemote.first();
    final AuthenticatedChatConnection.FakeChatRemote fakeRemote = chatAndFakeRemote.second();

    var request =
        new AuthenticatedChatConnection.Request(
            "PUT", "/some/path", Map.of("purpose", "test request"), new byte[] {1, 1, 2, 3}, 5000);
    var responseFuture = chat.send(request);

    var requestFromServerWithId = fakeRemote.getNextIncomingRequest().get();
    var requestFromServer = requestFromServerWithId.first();
    assertEquals(
        requestFromServer.guardedMap(NativeTesting::TESTING_ChatRequestGetMethod),
        request.method());
    assertEquals(
        requestFromServer.guardedMap(NativeTesting::TESTING_ChatRequestGetPath),
        request.pathAndQuery());
    assertArrayEquals(
        requestFromServer.guardedMap(NativeTesting::TESTING_ChatRequestGetBody), request.body());
    assertEquals(
        requestFromServer.guardedMap(
            req -> NativeTesting.TESTING_ChatRequestGetHeaderValue(req, "purpose")),
        "test request");
    assertEquals(requestFromServerWithId.second(), Long.valueOf(0));

    // 1: 0
    // 2: 201
    // 3: {"Created"}
    // 5: {"purpose: test response"}
    // 4: {5}
    injectServerResponse(fakeRemote, "CAAQyQEaB0NyZWF0ZWQqFnB1cnBvc2U6IHRlc3QgcmVzcG9uc2UiAQU=");

    var responseFromServer = responseFuture.get();
    assertEquals(responseFromServer.status(), 201);
    assertEquals(responseFromServer.message(), "Created");
    assertEquals(responseFromServer.headers(), Map.of("purpose", "test response"));
    assertArrayEquals(responseFromServer.body(), new byte[] {5});

    // Make sure the chat object doesn't get GC'd early.
    Native.keepAlive(chat);
  }

  // This test hangs until the listener object is cleaned up.
  // If it hangs for more than five seconds, consider that a failure.
  @Test(timeout = 5000)
  public void testListenerCleanup() throws Exception {
    class Listener implements ChatConnectionListener {
      CountDownLatch latch;

      Listener(CountDownLatch latch) {
        this.latch = latch;
      }

      public void onIncomingMessage(
          ChatConnection chat,
          byte[] envelope,
          long serverDeliveryTimestamp,
          ServerMessageAck sendAck) {}

      @Override
      @SuppressWarnings("deprecation")
      protected void finalize() {
        latch.countDown();
      }
    }

    final TokioAsyncContext tokioAsyncContext = new TokioAsyncContext();
    CountDownLatch latch = new CountDownLatch(1);
    var chatAndFake =
        AuthenticatedChatConnection.fakeConnect(tokioAsyncContext, new Listener(latch));

    System.gc();
    System.runFinalization();

    assertEquals(1, latch.getCount());

    chatAndFake = null;
    do {
      System.gc();
      System.runFinalization();
    } while (!latch.await(100, TimeUnit.MILLISECONDS));
  }
}
