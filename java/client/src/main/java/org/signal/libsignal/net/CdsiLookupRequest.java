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

  /**
   * @deprecated The requireAcis field is no longer read by the server. Use the overload that
   *     doesn't take it as an argument.
   */
  @Deprecated
  public CdsiLookupRequest(
      Set<String> previousE164s,
      Set<String> newE164s,
      Map<ServiceId, ProfileKey> serviceIds,
      boolean requireAcis,
      Optional<byte[]> token) {
    this(previousE164s, newE164s, serviceIds, token);
  }

  NativeRequest makeNative() {
    return new NativeRequest(
        this.previousE164s, this.newE164s, this.removedE164s, this.serviceIds, this.token);
  }

  class NativeRequest {
    private NativeRequest(
        Set<String> previousE164s,
        Set<String> newE164s,
        Set<String> removedE164s,
        Map<ServiceId, ProfileKey> serviceIds,
        byte[] token) {
      this.nativeHandle = Native.LookupRequest_new();

      for (String e164 : previousE164s) {
        Native.LookupRequest_addPreviousE164(this.nativeHandle, e164);
      }

      for (String e164 : newE164s) {
        Native.LookupRequest_addE164(this.nativeHandle, e164);
      }

      filterExceptions(
          () -> {
            for (Map.Entry<ServiceId, ProfileKey> entry : serviceIds.entrySet()) {
              Native.LookupRequest_addAciAndAccessKey(
                  this.nativeHandle,
                  entry.getKey().toServiceIdFixedWidthBinary(),
                  entry.getValue().deriveAccessKey());
            }
          });

      if (token != null) {
        Native.LookupRequest_setToken(this.nativeHandle, token);
      }
    }

    long getHandle() {
      return this.nativeHandle;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void finalize() {
      Native.LookupRequest_Destroy(this.nativeHandle);
    }

    private long nativeHandle;
  }
}
