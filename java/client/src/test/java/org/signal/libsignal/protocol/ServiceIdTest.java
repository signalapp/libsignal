//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol;

import java.util.UUID;
import junit.framework.TestCase;

import org.signal.libsignal.protocol.util.Hex;

public class ServiceIdTest extends TestCase {
    private static final String TEST_UUID_STRING = "c04d643e-1c2d-43b6-bcb7-d7f41f7f0990";
    private static final UUID TEST_UUID = UUID.fromString(TEST_UUID_STRING);
    private static final String TEST_UUID_HEX = "c04d643e1c2d43b6bcb7d7f41f7f0990";

    public void testFromUUIDAndBack() throws Exception {
        UUID original = UUID.randomUUID();
        ServiceId.Aci aci = new ServiceId.Aci(original);
        assertEquals(original, aci.getRawUUID());
        ServiceId.Pni pni = new ServiceId.Pni(original);
        assertEquals(original, pni.getRawUUID());
    }

    public void testAciRepresentations() throws Exception {
        ServiceId.Aci aci = new ServiceId.Aci(TEST_UUID);
        assertEquals(TEST_UUID_STRING, aci.toServiceIdString());
        assertEquals(TEST_UUID_HEX, Hex.toStringCondensed(aci.toServiceIdBinary()));
        assertEquals(String.format("<ACI:%s>", TEST_UUID_STRING), aci.toLogString());
        assertEquals(String.format("<ACI:%s>", TEST_UUID_STRING), aci.toString());
    } 

    public void testPniRepresentations() throws Exception {
        ServiceId.Pni pni = new ServiceId.Pni(TEST_UUID);
        assertEquals(String.format("PNI:%s", TEST_UUID_STRING), pni.toServiceIdString());
        assertEquals(String.format("01%s", TEST_UUID_HEX), Hex.toStringCondensed(pni.toServiceIdBinary()));
        assertEquals(String.format("<PNI:%s>", TEST_UUID_STRING), pni.toLogString());
        assertEquals(String.format("<PNI:%s>", TEST_UUID_STRING), pni.toString());
    }

    public void testParseFromString() throws Exception {
        assert(ServiceId.parseFromString(TEST_UUID_STRING) instanceof ServiceId.Aci);
        assert(ServiceId.parseFromString(String.format("PNI:%s", TEST_UUID_STRING)) instanceof ServiceId.Pni);
        try {
            ServiceId.parseFromString(String.format("ACI:%s", TEST_UUID_STRING));
            fail("Successfully parsed an invalid Service-Id-String");
        } catch (IllegalArgumentException ex) {
        }
    }

    public void testParseFromBinary() throws Exception {
        byte[] aciBytes = Hex.fromStringCondensedAssert(TEST_UUID_HEX);
        assert(ServiceId.parseFromBinary(aciBytes) instanceof ServiceId.Aci);
        byte[] pniBytes = Hex.fromStringCondensedAssert("01" + TEST_UUID_HEX);
        assert(ServiceId.parseFromBinary(pniBytes) instanceof ServiceId.Pni);
        byte[] invalidAciBytes = Hex.fromStringCondensedAssert("00" + TEST_UUID_HEX);
        try {
            ServiceId.parseFromBinary(invalidAciBytes);
            fail("Successfully parsed in invalid Service-Id-Binary");
        } catch (IllegalArgumentException ex) {
        }
    }

    public void testNullInputs() throws Exception {
        try {
            new ServiceId.Aci((UUID)null);
            fail("Should have failed");
        } catch (IllegalArgumentException ex){}
        try {
            new ServiceId.Pni((UUID)null);
            fail("Should have failed");
        } catch (IllegalArgumentException ex){}
        try {
            ServiceId.parseFromString((String)null);
            fail("Should have failed");
        } catch (IllegalArgumentException ex){}
        try {
            ServiceId.parseFromBinary((byte[])null);
            fail("Should have failed");
        } catch (IllegalArgumentException ex){}
    }

    public void testInvalidServiceId() throws Exception {
        try {
            byte[] invalidServiceIdBytes = Hex.fromStringCondensedAssert("02" + TEST_UUID_HEX);
            ServiceId.parseFromBinary(invalidServiceIdBytes);
            fail("Should have failed");
        } catch(IllegalArgumentException ex) {}
        try {
            String invalidServiceString = "SGL:" + TEST_UUID_STRING;
            ServiceId.parseFromString(invalidServiceString);
            fail("Should have failed");
        } catch(IllegalArgumentException ex) {}
    }
}
