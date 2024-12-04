//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import java.util.Optional;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.internal.NativeHandleGuard;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ServiceId.Aci;

/** Result of a key transparency search operation. */
public class SearchResult extends NativeHandleGuard.SimpleOwner {
  public SearchResult(long nativeHandle) {
    super(nativeHandle);
  }

  @Override
  protected void release(long nativeHandle) {
    Native.SearchResult_Destroy(nativeHandle);
  }

  public IdentityKey getAciIdentityKey() {
    long handle = this.guardedMap(Native::SearchResult_GetAciIdentityKey);
    return new IdentityKey(handle);
  }

  public Optional<Aci> getAciForE164() {
    byte[] aciBytes = this.guardedMap(Native::SearchResult_GetAciForE164);
    try {
      return Optional.ofNullable(aciBytes == null ? null : Aci.parseFromFixedWidthBinary(aciBytes));
    } catch (ServiceId.InvalidServiceIdException ex) {
      throw new AssertionError("Invalid serialized ACI", ex);
    }
  }

  public Optional<Aci> getAciForUsernameHash() {
    byte[] aciBytes = this.guardedMap(Native::SearchResult_GetAciForUsernameHash);
    try {
      return Optional.ofNullable(aciBytes == null ? null : Aci.parseFromFixedWidthBinary(aciBytes));
    } catch (ServiceId.InvalidServiceIdException ex) {
      throw new AssertionError("Invalid serialized ACI", ex);
    }
  }

  // This is effectively an implementation of Store.applyUpdates method.
  // Intentionally package private. Defined here to have SearchResult native APIs in one place.
  void updateStore(Aci aci, Store store) {
    byte[] accountData = this.guardedMap(Native::SearchResult_GetAccountData);
    if (accountData != null) {
      store.setAccountData(aci, accountData);
    }
  }
}
