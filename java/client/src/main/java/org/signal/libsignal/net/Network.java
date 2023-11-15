//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.function.Function;
import org.signal.libsignal.internal.Native;

public class Network {
  public enum Environment {
    STAGING(0),
    PRODUCTION(1);

    private final int value;

    private Environment(int value) {
      this.value = value;
    }
  }

  public Network(Environment env) {
    this.asyncRuntimeHandle = Native.TokioAsyncContext_new();
    this.connectionManagerHandle = Native.ConnectionManager_new(env.value);
  }

  public Future<CdsiLookupResponse> cdsiLookup(
      String username, String password, CdsiLookupRequest request, Duration timeout)
      throws IOException, InterruptedException, ExecutionException {
    int timeoutMillis;
    try {
      timeoutMillis = Math.toIntExact(timeout.toMillis());
    } catch (ArithmeticException e) {
      timeoutMillis = Integer.MAX_VALUE;
    }

    CdsiLookupRequest.NativeRequest nativeRequest = request.makeNative();

    // The output from the bridging layer is untyped, but we're pretty sure it's
    // a map from E164 strings to typed entries.
    @SuppressWarnings("unchecked")
    Function<Map, CdsiLookupResponse> convertResponse =
        (Map untypedResult) ->
            new CdsiLookupResponse((Map<String, CdsiLookupResponse.Entry>) (untypedResult));

    return Native.CdsiLookup(
            this.asyncRuntimeHandle,
            this.connectionManagerHandle,
            username,
            password,
            nativeRequest.getHandle(),
            timeoutMillis)
        .thenApply(convertResponse);
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() {
    Native.ConnectionManager_Destroy(this.connectionManagerHandle);
    Native.TokioAsyncContext_Destroy(this.asyncRuntimeHandle);
  }

  private long asyncRuntimeHandle;
  private long connectionManagerHandle;
}
