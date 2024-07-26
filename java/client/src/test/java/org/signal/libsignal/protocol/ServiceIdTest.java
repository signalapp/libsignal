//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId.InvalidServiceIdException;
import org.signal.libsignal.protocol.util.Hex;

public class ServiceIdTest {
  private static final String TEST_UUID_STRING = "c04d643e-1c2d-43b6-bcb7-d7f41f7f0990";
  private static final UUID TEST_UUID = UUID.fromString(TEST_UUID_STRING);
  private static final String TEST_UUID_HEX = "c04d643e1c2d43b6bcb7d7f41f7f0990";

  @Test
  public void testFromUUIDAndBack() throws Exception {
    UUID original = UUID.randomUUID();
    ServiceId.Aci aci = new ServiceId.Aci(original);
    assertEquals(original, aci.getRawUUID());
    ServiceId.Pni pni = new ServiceId.Pni(original);
    assertEquals(original, pni.getRawUUID());
  }

  @Test
  public void testAciRepresentations() throws Exception {
    ServiceId.Aci aci = new ServiceId.Aci(TEST_UUID);
    assertEquals(TEST_UUID_STRING, aci.toServiceIdString());
    assertEquals(TEST_UUID_HEX, Hex.toStringCondensed(aci.toServiceIdBinary()));
    assertEquals(String.format("<ACI:%s>", TEST_UUID_STRING), aci.toLogString());
    assertEquals(String.format("<ACI:%s>", TEST_UUID_STRING), aci.toString());
  }

  @Test
  public void testPniRepresentations() throws Exception {
    ServiceId.Pni pni = new ServiceId.Pni(TEST_UUID);
    assertEquals(String.format("PNI:%s", TEST_UUID_STRING), pni.toServiceIdString());
    assertEquals(
        String.format("01%s", TEST_UUID_HEX), Hex.toStringCondensed(pni.toServiceIdBinary()));
    assertEquals(String.format("<PNI:%s>", TEST_UUID_STRING), pni.toLogString());
    assertEquals(String.format("<PNI:%s>", TEST_UUID_STRING), pni.toString());
  }

  @Test
  public void testParseFromString() throws Exception {
    assert (ServiceId.parseFromString(TEST_UUID_STRING) instanceof ServiceId.Aci);
    ServiceId.Aci.parseFromString(TEST_UUID_STRING);

    assert (ServiceId.parseFromString(String.format("PNI:%s", TEST_UUID_STRING))
        instanceof ServiceId.Pni);
    ServiceId.Pni.parseFromString(String.format("PNI:%s", TEST_UUID_STRING));

    assertThrows(
        InvalidServiceIdException.class,
        () -> ServiceId.parseFromString(String.format("ACI:%s", TEST_UUID_STRING)));
  }

  @Test
  public void testParseFromBinary() throws Exception {
    byte[] aciBytes = Hex.fromStringCondensedAssert(TEST_UUID_HEX);
    assert (ServiceId.parseFromBinary(aciBytes) instanceof ServiceId.Aci);
    ServiceId.Aci.parseFromBinary(aciBytes);

    byte[] pniBytes = Hex.fromStringCondensedAssert("01" + TEST_UUID_HEX);
    assert (ServiceId.parseFromBinary(pniBytes) instanceof ServiceId.Pni);
    ServiceId.Pni.parseFromBinary(pniBytes);

    byte[] invalidAciBytes = Hex.fromStringCondensedAssert("00" + TEST_UUID_HEX);
    assertThrows(InvalidServiceIdException.class, () -> ServiceId.parseFromBinary(invalidAciBytes));
  }

  @Test
  public void testNullInputs() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> new ServiceId.Aci((UUID) null));
    assertThrows(IllegalArgumentException.class, () -> new ServiceId.Pni((UUID) null));
    assertThrows(InvalidServiceIdException.class, () -> ServiceId.parseFromString(null));
    assertThrows(InvalidServiceIdException.class, () -> ServiceId.parseFromBinary(null));
  }

  @Test
  public void testInvalidServiceId() throws Exception {
    assertThrows(
        InvalidServiceIdException.class,
        () -> {
          byte[] invalidServiceIdBytes = Hex.fromStringCondensedAssert("02" + TEST_UUID_HEX);
          ServiceId.parseFromBinary(invalidServiceIdBytes);
        });
    assertThrows(
        InvalidServiceIdException.class,
        () -> {
          String invalidServiceString = "SGL:" + TEST_UUID_STRING;
          ServiceId.parseFromString(invalidServiceString);
        });
  }

  @Test
  public void testOrdering() throws Exception {
    // creates an immutabale list
    List<ServiceId> original =
        List.of(
            new ServiceId.Aci(new UUID(0, 0)),
            new ServiceId.Aci(TEST_UUID),
            new ServiceId.Pni(new UUID(0, 0)),
            new ServiceId.Pni(TEST_UUID));
    // copying to another list
    List<ServiceId> ids = new ArrayList<>(original);
    Collections.shuffle(ids);
    Collections.sort(ids);
    assertEquals(original, ids);
  }
}
