//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.keytrans;

import java.util.HashMap;
import java.util.Optional;
import org.signal.libsignal.protocol.ServiceId;

public class TestStore implements Store {

  public HashMap<ServiceId.Aci, byte[]> storage = new HashMap<>();
  public byte[] lastDistinguishedTreeHead;

  @Override
  public Optional<byte[]> getLastDistinguishedTreeHead() {
    return Optional.ofNullable(lastDistinguishedTreeHead);
  }

  @Override
  public void setLastDistinguishedTreeHead(byte[] lastDistinguishedTreeHead) {
    this.lastDistinguishedTreeHead = lastDistinguishedTreeHead;
  }

  @Override
  public Optional<byte[]> getAccountData(ServiceId.Aci aci) {
    return Optional.ofNullable(this.storage.get(aci));
  }

  @Override
  public void setAccountData(ServiceId.Aci aci, byte[] data) {
    this.storage.put(aci, data);
  }
}
