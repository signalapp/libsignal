//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

package org.signal.zkgroup;

import org.junit.Test;
import org.signal.zkgroup.util.UUIDUtil;

import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.signal.zkgroup.internal.*;
import java.io.IOException;

public final class UUIDUtilTest {

  @Test
  public void serialize() throws IOException {
    UUID uuid = UUID.fromString("67dfd496-ea02-4720-b13d-83a462168b1d");

    byte[] serialized = UUIDUtil.serialize(uuid);

    assertArrayEquals(Hex.fromStringCondensed("67dfd496ea024720b13d83a462168b1d"), serialized);
  }

  @Test
  public void serialize_alternativeValues() throws IOException {
    UUID uuid = UUID.fromString("b70df6ac-3b21-4b39-a514-613561f51e2a");

    byte[] serialized = UUIDUtil.serialize(uuid);

    assertArrayEquals(Hex.fromStringCondensed("b70df6ac3b214b39a514613561f51e2a"), serialized);
  }

  @Test
  public void deserialize() throws IOException {
    byte[] bytes = Hex.fromStringCondensed("3dc48790568b49c19bd6ab6604a5bc32");

    UUID uuid = UUIDUtil.deserialize(bytes);

    assertEquals("3dc48790-568b-49c1-9bd6-ab6604a5bc32", uuid.toString());
  }

  @Test
  public void deserialize_alternativeValues() throws IOException {
    byte[] bytes = Hex.fromStringCondensed("b83dfb0b67f141aa992e030c167cd011");

    UUID uuid = UUIDUtil.deserialize(bytes);

    assertEquals("b83dfb0b-67f1-41aa-992e-030c167cd011", uuid.toString());
  }
}
