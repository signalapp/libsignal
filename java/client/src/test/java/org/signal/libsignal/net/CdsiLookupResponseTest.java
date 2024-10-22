//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.junit.Test;
import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.internal.NativeTesting;
import org.signal.libsignal.protocol.ServiceId;

public class CdsiLookupResponseTest {
  public final String e164Both = "+18005551011";
  public final String e164Pni = "+18005551012";

  public final String aciUuid = "9d0652a3-dcc3-4d11-975f-74d61598733f";
  public final String pniUuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f";

  public final int debugPermitsUsed = 123;

  @Test
  public void cdsiLookupResponseConvert()
      throws ServiceId.InvalidServiceIdException, ExecutionException, InterruptedException {
    ServiceId.Aci aci = new ServiceId.Aci(UUID.fromString(aciUuid));
    ServiceId.Pni pni = new ServiceId.Pni(UUID.fromString(pniUuid));

    CdsiLookupResponse expected =
        new CdsiLookupResponse(
            Map.of(
                this.e164Both, new CdsiLookupResponse.Entry(aci, pni),
                this.e164Pni, new CdsiLookupResponse.Entry(null, pni)),
            this.debugPermitsUsed);

    TokioAsyncContext context = new TokioAsyncContext();
    Future<Object> response;

    try (NativeHandleGuard guard = new NativeHandleGuard(context)) {
      response = NativeTesting.TESTING_CdsiLookupResponseConvert(guard.nativeHandle());
    }

    CdsiLookupResponse actual = (CdsiLookupResponse) response.get();
    assertEquals(expected, actual);
  }

  @Test
  public void cdsiLookupErrorConvert() {
    assertLookupErrorIs(
        "Protocol", CdsiProtocolException.class, "Protocol error after establishing a connection");
    assertLookupErrorIs("CdsiProtocol", CdsiProtocolException.class, "Response token was missing");
    assertLookupErrorIs(
        "AttestationDataError",
        AttestationDataException.class,
        "attestation data invalid: fake reason");
    assertLookupErrorIs(
        "InvalidResponse",
        CdsiProtocolException.class,
        "Invalid response received from the server");
    RetryLaterException retryLater =
        assertLookupErrorIs(
            "RetryAfter42Seconds", RetryLaterException.class, "Retry after 42 seconds");
    assertEquals(retryLater.duration, Duration.ofSeconds(42));

    assertLookupErrorIs(
        "InvalidToken", CdsiInvalidTokenException.class, "Request token was invalid");
    assertLookupErrorIs(
        "InvalidArgument",
        IllegalArgumentException.class,
        "invalid argument: request was invalid: fake reason");
    assertLookupErrorIs(
        "Parse", CdsiProtocolException.class, "Failed to parse the response from the server");
    assertLookupErrorIs("ConnectDnsFailed", IOException.class, "DNS lookup failed");
    assertLookupErrorIs(
        "WebSocketIdleTooLong", NetworkException.class, "channel was idle for too long");
    assertLookupErrorIs("ConnectionTimedOut", NetworkException.class, "connect timed out");
    assertLookupErrorIs("ServerCrashed", CdsiProtocolException.class, "Server error: crashed");
  }

  private static <E extends Exception> E assertLookupErrorIs(
      String errorDescription, Class<E> expectedErrorType, String expectedMessage) {
    E e =
        assertThrows(
            "for " + errorDescription,
            expectedErrorType,
            () -> NativeTesting.TESTING_CdsiLookupErrorConvert(errorDescription));
    assertEquals(e.getMessage(), expectedMessage);
    return e;
  }
}
