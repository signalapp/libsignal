//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.ServiceId;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class ProtocolAddressTest {
  @Test
  public void testRoundTripServiceId() {
    UUID uuid = UUID.randomUUID();
    ServiceId aci = new ServiceId.Aci(uuid);
    ServiceId pni = new ServiceId.Pni(uuid);

    SignalProtocolAddress aciAddr = new SignalProtocolAddress(aci, 1);
    SignalProtocolAddress pniAddr = new SignalProtocolAddress(pni, 1);
    assertNotEquals(aciAddr, pniAddr);
    assertEquals(aci, aciAddr.getServiceId());
    assertEquals(pni, pniAddr.getServiceId());
  }
}
