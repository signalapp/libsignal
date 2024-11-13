//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import org.signal.libsignal.internal.FilterExceptions;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;

/**
 * Extra data accompanying the key transparency search request.
 *
 * <p>This is an implementation detail of the {@link org.signal.libsignal.net.KeyTransparencyClient}
 * and is not supposed to be used directly. The context will be populated from the {@link Store}.
 */
public final class SearchContext extends NativeHandleGuard.SimpleOwner {
  SearchContext(
      byte[] aciMonitor,
      byte[] e164Monitor,
      byte[] usernameHashMonitor,
      byte[] lastTreeHead,
      byte[] lastDistinguishedTreeHead) {
    super(
        FilterExceptions.filterExceptions(
            () ->
                // The only exception it can throw is an IllegalArgumentException, even though it is
                // bridged as throwing Exception.
                Native.KeyTransparency_NewSearchContext(
                    aciMonitor,
                    e164Monitor,
                    usernameHashMonitor,
                    lastTreeHead,
                    lastDistinguishedTreeHead)));
  }

  @Override
  protected void release(long nativeHandle) {
    Native.ChatSearchContext_Destroy(nativeHandle);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    byte[] aciMonitor;
    byte[] e164Monitor;
    byte[] usernameHashMonitor;
    byte[] lastTreeHead;
    byte[] lastDistinguishedTreeHead;

    public SearchContext build() {
      return new SearchContext(
          aciMonitor, e164Monitor, usernameHashMonitor, lastTreeHead, lastDistinguishedTreeHead);
    }

    public Builder withAciMonitor(byte[] aciMonitor) {
      this.aciMonitor = aciMonitor;
      return this;
    }

    public Builder withE164Monitor(byte[] e164Monitor) {
      this.e164Monitor = e164Monitor;
      return this;
    }

    public Builder withUsernameHashMonitor(byte[] usernameHashMonitor) {
      this.usernameHashMonitor = usernameHashMonitor;
      return this;
    }

    public Builder withLastTreeHead(byte[] lastTreeHead) {
      this.lastTreeHead = lastTreeHead;
      return this;
    }

    public Builder withLastDistinguishedTreeHead(byte[] lastDistinguishedTreeHead) {
      this.lastDistinguishedTreeHead = lastDistinguishedTreeHead;
      return this;
    }
  }
}
