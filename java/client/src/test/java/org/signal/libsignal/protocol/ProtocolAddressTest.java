//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;

import java.util.UUID;
import org.junit.Test;

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

  @Test
  public void testInvalidDeviceId() {
    UUID uuid = UUID.randomUUID();
    ServiceId aci = new ServiceId.Aci(uuid);

    var exception =
        assertThrows(IllegalArgumentException.class, () -> new SignalProtocolAddress(aci, 1234));

    assertThat(exception.getMessage(), containsString(aci.toServiceIdString()));
    assertThat(exception.getMessage(), containsString("1234"));
  }
}
