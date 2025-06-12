//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import static org.signal.libsignal.internal.FilterExceptions.filterExceptions;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;

public class CdsiLookupRequest {
  final Set<String> previousE164s;
  final Set<String> newE164s;
  final Set<String> removedE164s;

  final Map<ServiceId, ProfileKey> serviceIds;

  final byte[] token;

  public CdsiLookupRequest(
      Set<String> previousE164s,
      Set<String> newE164s,
      Map<ServiceId, ProfileKey> serviceIds,
      Optional<byte[]> token) {
    if (previousE164s.size() > 0 && !token.isPresent()) {
      throw new IllegalArgumentException("You must have a token if you have previousE164s!");
    }

    this.previousE164s = previousE164s;
    this.newE164s = newE164s;
    this.removedE164s = Collections.emptySet();
    this.serviceIds = serviceIds;
    this.token = token.orElse(null);
  }

  NativeRequest makeNative() {
    return new NativeRequest(
        this.previousE164s, this.newE164s, this.removedE164s, this.serviceIds, this.token);
  }

  class NativeRequest extends NativeHandleGuard.SimpleOwner {
    private NativeRequest(
        Set<String> previousE164s,
        Set<String> newE164s,
        Set<String> removedE164s,
        Map<ServiceId, ProfileKey> serviceIds,
        byte[] token) {
      super(Native.LookupRequest_new());
      guardedRun(
          (nativeHandle) -> {
            for (String e164 : previousE164s) {
              Native.LookupRequest_addPreviousE164(nativeHandle, e164);
            }

            for (String e164 : newE164s) {
              Native.LookupRequest_addE164(nativeHandle, e164);
            }

            filterExceptions(
                () -> {
                  for (Map.Entry<ServiceId, ProfileKey> entry : serviceIds.entrySet()) {
                    Native.LookupRequest_addAciAndAccessKey(
                        nativeHandle,
                        entry.getKey().toServiceIdFixedWidthBinary(),
                        entry.getValue().deriveAccessKey());
                  }
                });

            if (token != null) {
              Native.LookupRequest_setToken(nativeHandle, token);
            }
          });
    }

    @Override
    protected void release(long nativeHandle) {
      Native.LookupRequest_Destroy(nativeHandle);
    }
  }
}
