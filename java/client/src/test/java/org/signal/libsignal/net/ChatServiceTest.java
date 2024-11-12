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
import org.junit.Assume;
import org.junit.Test;
import org.signal.libsignal.internal.NativeTesting;
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
    final ChatService.Response response1 =
        (ChatService.Response) NativeTesting.TESTING_ChatServiceResponseConvert(false);
    assertEquals(EXPECTED_STATUS, response1.status());
    assertEquals(EXPECTED_MESSAGE, response1.message());
    assertArrayEquals(new byte[0], response1.body());
    assertEquals(EXPECTED_HEADERS, response1.headers());

    final ChatService.Response response2 =
        (ChatService.Response) NativeTesting.TESTING_ChatServiceResponseConvert(true);
    assertEquals(EXPECTED_STATUS, response2.status());
    assertEquals(EXPECTED_MESSAGE, response2.message());
    assertArrayEquals(EXPECTED_CONTENT, response2.body());
    assertEquals(EXPECTED_HEADERS, response2.headers());
  }

  @Test
  public void testConvertDebugInfo() throws Exception {
    final ChatService.DebugInfo debugInfo =
        (ChatService.DebugInfo) NativeTesting.TESTING_ChatServiceDebugInfoConvert();
    assertEquals(IpType.IPv4, debugInfo.ipType());
    assertEquals(200, debugInfo.durationMs());
    assertEquals("connection_info", debugInfo.connectionInfo());
  }

  @Test
  public void testConvertResponseAndDebugInfo() throws Exception {
    final ChatService.ResponseAndDebugInfo responseAndDebugInfo =
        (ChatService.ResponseAndDebugInfo)
            NativeTesting.TESTING_ChatServiceResponseAndDebugInfoConvert();

    final ChatService.Response response = responseAndDebugInfo.response();
    assertEquals(EXPECTED_STATUS, response.status());
    assertEquals(EXPECTED_MESSAGE, response.message());
    assertArrayEquals(EXPECTED_CONTENT, response.body());
    assertEquals(EXPECTED_HEADERS, response.headers());

    final ChatService.DebugInfo debugInfo = responseAndDebugInfo.debugInfo();
    assertEquals(IpType.IPv4, debugInfo.ipType());
  }

  @Test
  public void cdsiLookupErrorConvert() {
    assertChatServiceErrorIs("AppExpired", AppExpiredException.class);
    assertChatServiceErrorIs("DeviceDeregistered", DeviceDeregisteredException.class);
    assertChatServiceErrorIs("ServiceInactive", ChatServiceInactiveException.class);

    assertChatServiceErrorIs("WebSocket", ChatServiceException.class);
    assertChatServiceErrorIs("UnexpectedFrameReceived", ChatServiceException.class);
    assertChatServiceErrorIs("ServerRequestMissingId", ChatServiceException.class);
    assertChatServiceErrorIs("IncomingDataInvalid", ChatServiceException.class);
    assertChatServiceErrorIs("Timeout", ChatServiceException.class);
    assertChatServiceErrorIs("TimeoutEstablishingConnection", ChatServiceException.class);
    RetryLaterException retryLater =
        assertChatServiceErrorIs("RetryAfter42Seconds", RetryLaterException.class);
    assertEquals(retryLater.duration, Duration.ofSeconds(42));

    // These two are more of internal errors, but they should never happen anyway.
    assertChatServiceErrorIs("FailedToPassMessageToIncomingChannel", ChatServiceException.class);
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
    final ChatService.Request request =
        new ChatService.Request(
            expectedMethod, expectedPathAndQuery, EXPECTED_HEADERS, EXPECTED_CONTENT, 5000);
    final ChatService.InternalRequest internal = ChatService.buildInternalRequest(request);
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

  @Test
  public void testConnectUnauth() throws Exception {
    // Use the presence of the proxy server environment setting to know whether we should make
    // network requests in our tests.
    final String PROXY_SERVER = TestEnvironment.get("LIBSIGNAL_TESTING_PROXY_SERVER");
    Assume.assumeNotNull(PROXY_SERVER);

    final Network net = new Network(Network.Environment.STAGING, USER_AGENT);
    final UnauthenticatedChatService chat = net.createUnauthChatService(null);
    // Just make sure we can connect.
    chat.connect().get();
    chat.disconnect();
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

    final UnauthenticatedChatService chat = net.createUnauthChatService(null);
    // Just make sure we can connect.
    chat.connect().get();
    chat.disconnect();
  }

  @Test
  public void testInvalidProxyRejected() throws Exception {
    // The default TLS proxy config doesn't support staging, so we connect to production.
    final Network net = new Network(Network.Environment.PRODUCTION, USER_AGENT);
    assertThrows(IOException.class, () -> net.setProxy("signalfoundation.org", 0));
    assertThrows(IOException.class, () -> net.setProxy("signalfoundation.org", 100_000));
    assertThrows(IOException.class, () -> net.setProxy("signalfoundation.org", -1));
  }

  private void injectServerRequest(ChatService chat, String requestBase64) {
    chat.guardedRun(
        chatHandle ->
            NativeTesting.TESTING_ChatService_InjectRawServerRequest(
                chatHandle, Base64.decode(requestBase64)));
  }

  @Test
  public void testListenerCallbacks() throws Exception {
    class Listener implements ChatListener {
      boolean receivedMessage1;
      boolean receivedMessage2;
      boolean receivedQueueEmpty;
      Throwable error;
      CountDownLatch latch = new CountDownLatch(1);

      public void onIncomingMessage(
          ChatService chat,
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

      public void onQueueEmpty(ChatService chat) {
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

      public void onConnectionInterrupted(ChatService chat, ChatServiceException disconnectReason) {
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

    final Network net = new Network(Network.Environment.STAGING, USER_AGENT);
    final Listener listener = new Listener();
    final ChatService chat = net.createAuthChatService("", "", false, listener);

    // The following payloads were generated via protoscope.
    // % protoscope -s | base64
    // The fields are described by chat_websocket.proto in the libsignal-net crate.

    // 1: {"PUT"}
    // 2: {"/api/v1/message"}
    // 3: {1000i64}
    // 5: {"x-signal-timestamp:1000"}
    // 4: 1
    injectServerRequest(
        chat, "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI6AMAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoxMDAwIAE=");
    // 1: {"PUT"}
    // 2: {"/api/v1/message"}
    // 3: {2000i64}
    // 5: {"x-signal-timestamp:2000"}
    // 4: 2
    injectServerRequest(
        chat, "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI0AcAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoyMDAwIAI=");

    // Sending an invalid message should not affect the listener at all, nor should it stop future
    // requests.
    // 1: {"PUT"}
    // 2: {"/invalid"}
    // 4: 10
    injectServerRequest(chat, "CgNQVVQSCC9pbnZhbGlkIAo=");

    // 1: {"PUT"}
    // 2: {"/api/v1/queue/empty"}
    // 4: 99
    injectServerRequest(chat, "CgNQVVQSEy9hcGkvdjEvcXVldWUvZW1wdHkgYw==");

    chat.guardedRun(NativeTesting::TESTING_ChatService_InjectConnectionInterrupted);

    listener.latch.await();
    assertNull(listener.error);
  }

  // This test hangs until the listener object is cleaned up.
  // If it hangs for more than five seconds, consider that a failure.
  @Test(timeout = 5000)
  public void testListenerCleanup() throws Exception {
    class Listener implements ChatListener {
      CountDownLatch latch;

      Listener(CountDownLatch latch) {
        this.latch = latch;
      }

      public void onIncomingMessage(
          ChatService chat,
          byte[] envelope,
          long serverDeliveryTimestamp,
          ServerMessageAck sendAck) {}

      @Override
      @SuppressWarnings("deprecation")
      protected void finalize() {
        latch.countDown();
      }
    }

    final Network net = new Network(Network.Environment.STAGING, USER_AGENT);
    CountDownLatch latch = new CountDownLatch(1);
    ChatService chat = net.createAuthChatService("", "", false, new Listener(latch));

    System.gc();
    System.runFinalization();

    assertEquals(1, latch.getCount());

    chat = null;
    do {
      System.gc();
      System.runFinalization();
    } while (!latch.await(100, TimeUnit.MILLISECONDS));
  }
}
