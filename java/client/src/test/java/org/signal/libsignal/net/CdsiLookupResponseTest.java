//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.junit.Assert.*;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.junit.Test;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
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
      response = Native.TESTING_CdsiLookupResponseConvert(guard.nativeHandle());
    }

    CdsiLookupResponse actual = (CdsiLookupResponse) response.get();
    assertEquals(expected, actual);
  }

  @Test
  public void cdsiLookupErrorConvert() {
    assertThrows(java.lang.Exception.class, () -> Native.TESTING_CdsiLookupErrorConvert());
  }
}
