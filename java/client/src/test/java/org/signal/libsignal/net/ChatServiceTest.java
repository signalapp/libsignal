//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.Assume;
import org.junit.Test;
import org.signal.libsignal.internal.NativeTesting;
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
    final ChatService chat = net.createChatService("", "", false);
    // Just make sure we can connect.
    chat.connectUnauthenticated().get();
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

    final ChatService chat = net.createChatService("", "", false);
    // Just make sure we can connect.
    chat.connectUnauthenticated().get();
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
}
