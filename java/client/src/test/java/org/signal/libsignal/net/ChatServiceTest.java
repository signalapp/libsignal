//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.Test;
import org.signal.libsignal.internal.Native;

public class ChatServiceTest {

  private static final int EXPECTED_STATUS = 200;

  private static final String EXPECTED_MESSAGE = "OK";

  private static final byte[] EXPECTED_CONTENT = "content".getBytes(StandardCharsets.UTF_8);

  private static final Map<String, String> EXPECTED_HEADERS =
      Map.of(
          "user-agent", "test",
          "forwarded", "1.1.1.1");

  @Test
  public void testConvertResponse() throws Exception {
    // empty body
    final ChatService.Response response1 =
        (ChatService.Response) Native.TESTING_ChatServiceResponseConvert(false);
    assertEquals(EXPECTED_STATUS, response1.status());
    assertEquals(EXPECTED_MESSAGE, response1.message());
    assertArrayEquals(new byte[0], response1.body());
    assertEquals(EXPECTED_HEADERS, response1.headers());

    final ChatService.Response response2 =
        (ChatService.Response) Native.TESTING_ChatServiceResponseConvert(true);
    assertEquals(EXPECTED_STATUS, response2.status());
    assertEquals(EXPECTED_MESSAGE, response2.message());
    assertArrayEquals(EXPECTED_CONTENT, response2.body());
    assertEquals(EXPECTED_HEADERS, response2.headers());
  }

  @Test
  public void testConvertDebugInfo() throws Exception {
    final ChatService.DebugInfo debugInfo =
        (ChatService.DebugInfo) Native.TESTING_ChatServiceDebugInfoConvert();
    assertEquals(2, debugInfo.reconnectCount());
    assertEquals(IpType.IPv4, debugInfo.ipType());
    assertEquals(200, debugInfo.durationMs());
    assertEquals("connection_info", debugInfo.connectionInfo());
  }

  @Test
  public void testConvertResponseAndDebugInfo() throws Exception {
    final ChatService.ResponseAndDebugInfo responseAndDebugInfo =
        (ChatService.ResponseAndDebugInfo) Native.TESTING_ChatServiceResponseAndDebugInfoConvert();

    final ChatService.Response response = responseAndDebugInfo.response();
    assertEquals(EXPECTED_STATUS, response.status());
    assertEquals(EXPECTED_MESSAGE, response.message());
    assertArrayEquals(EXPECTED_CONTENT, response.body());
    assertEquals(EXPECTED_HEADERS, response.headers());

    final ChatService.DebugInfo debugInfo = responseAndDebugInfo.debugInfo();
    assertEquals(2, debugInfo.reconnectCount());
    assertEquals(IpType.IPv4, debugInfo.ipType());
  }

  @Test(expected = ChatServiceException.class)
  public void testConvertError() throws Exception {
    Native.TESTING_ChatServiceErrorConvert();
  }

  @Test(expected = ChatServiceInactiveException.class)
  public void testConvertInactiveError() throws Exception {
    Native.TESTING_ChatServiceInactiveErrorConvert();
  }

  @Test
  public void testConstructRequest() throws Exception {
    final String expectedMethod = "GET";
    final String expectedPathAndQuery = "/test";
    final ChatService.Request request =
        new ChatService.Request(
            expectedMethod, expectedPathAndQuery, EXPECTED_HEADERS, EXPECTED_CONTENT, 5000);
    final ChatService.InternalRequest internal = ChatService.buildInternalRequest(request);
    assertEquals(expectedMethod, internal.guardedMap(Native::TESTING_ChatRequestGetMethod));
    assertEquals(expectedPathAndQuery, internal.guardedMap(Native::TESTING_ChatRequestGetPath));
    assertArrayEquals(EXPECTED_CONTENT, internal.guardedMap(Native::TESTING_ChatRequestGetBody));
    EXPECTED_HEADERS.forEach(
        (name, value) ->
            assertEquals(
                value,
                internal.guardedMap(h -> Native.TESTING_ChatRequestGetHeaderValue(h, name))));
  }
}
