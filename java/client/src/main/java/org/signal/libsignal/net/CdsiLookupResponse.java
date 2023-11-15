//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net;

import java.util.Map;
import java.util.Objects;
import org.signal.libsignal.protocol.ServiceId;

public class CdsiLookupResponse {
  public static class Entry {
    Entry(byte[] aci, byte[] pni) throws ServiceId.InvalidServiceIdException {
      this(
          aci != null ? ServiceId.Aci.parseFromFixedWidthBinary(aci) : null,
          pni != null ? ServiceId.Pni.parseFromFixedWidthBinary(pni) : null);
    }

    public Entry(ServiceId.Aci aci, ServiceId.Pni pni) {
      this.aci = aci;
      this.pni = pni;
    }

    public String toString() {
      return "{aci: " + aci + ", pni: " + pni + "}";
    }

    public boolean equals(Object obj) {
      if (obj instanceof Entry) {
        Entry other = (Entry) obj;
        return Objects.equals(this.aci, other.aci) && Objects.equals(this.pni, other.pni);
      }
      return false;
    }

    public int hashCode() {
      return Objects.hash(this.aci, this.pni);
    }

    public final ServiceId.Aci aci;
    public final ServiceId.Pni pni;
  }

  CdsiLookupResponse(Map<String, Entry> entries) {
    this.entries = entries;
  }

  public Map<String, Entry> entries() {
    return this.entries;
  }

  public String toString() {
    return "{entries: " + entries + "}";
  }

  public boolean equals(Object obj) {
    if (obj instanceof CdsiLookupResponse) {
      return Objects.equals(this.entries, ((CdsiLookupResponse) obj).entries);
    }
    return false;
  }

  public int hashCode() {
    return this.entries.hashCode();
  }

  private final Map<String, Entry> entries;
}
