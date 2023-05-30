//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.svr2;

import org.junit.Test;
import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.protocol.kdf.HKDF;
import org.signal.libsignal.protocol.util.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

public class PinTest {

    @Test(expected = IllegalArgumentException.class)
    public void badSaltLength() {
        PinHash.svr1("password".getBytes(StandardCharsets.UTF_8), new byte[]{(byte) 0xFF});
    }

    @Test(expected = IllegalArgumentException.class)
    public void badEncodedHash() {
        Pin.verifyLocalHash("not-a-hash", "password".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void verify() {
        byte[] pin = "password".getBytes(StandardCharsets.UTF_8);
        String pwhash = Pin.localHash(pin);
        assertTrue(Pin.verifyLocalHash(pwhash, pin));
        assertFalse(Pin.verifyLocalHash(pwhash, "badpassword".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void known() throws IOException {
        final byte[] salt = Hex.fromStringCondensed("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        final byte[] pin = "password".getBytes(StandardCharsets.UTF_8);

        final PinHash pinHash = PinHash.svr1(pin, salt);
        assertArrayEquals(
                pinHash.accessKey(),
                Hex.fromStringCondensed("ab7e8499d21f80a6600b3b9ee349ac6d72c07e3359fe885a934ba7aa844429f8"));

        assertArrayEquals(
                pinHash.encryptionKey(),
                Hex.fromStringCondensed("44652df80490fc66bb864a9e638b2f7dc9e20649671dd66bbb9c37bee2bfecf1")
        );
    }

    @Test
    public void known2() throws IOException {
        final byte[] salt = Hex.fromStringCondensed("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        final byte[] pin = "anotherpassword".getBytes(StandardCharsets.UTF_8);

        final PinHash pinHash = PinHash.svr1(pin, salt);
        assertArrayEquals(
                pinHash.accessKey(),
                Hex.fromStringCondensed("301d9dd1e96f20ce51083f67d3298fd37b97525de8324d5e12ed2d407d3d927b"));

        assertArrayEquals(
                pinHash.encryptionKey(),
                Hex.fromStringCondensed("b6f16aa0591732e339b7e99cdd5fd6586a1c285c9d66876947fd82f66ed99757")
        );
    }

    private static byte[] bebytes(final long l) {
        final ByteBuffer bb = ByteBuffer.allocate(8);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putLong(l);
        return bb.array();
    }

    @Test
    public void testSaltWithGroupId() throws IOException, AttestationDataException {
        final byte[] mrenclave = Hex.fromStringCondensed("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95");
        final byte[] pin = "password".getBytes(StandardCharsets.UTF_8);
        final String username = "username";
        final long groupId = Long.parseUnsignedLong("15525669046665930652");
        final PinHash actual = PinHash.svr2(pin, username, mrenclave);

        // svr2 hash should use salt derrived froup groupId
        final byte[] expectedSalt = HKDF.deriveSecrets(username.getBytes(StandardCharsets.UTF_8), bebytes(groupId), new byte[]{}, 32);
        final byte[] knownSalt = Hex.fromStringCondensed("260d1f6d233c9326e8ba744e778b7b127147c7211d9bc3219ab3b7394766c508");
        assertArrayEquals(knownSalt, expectedSalt);

        final PinHash expected = PinHash.svr1(pin, expectedSalt);
        assertArrayEquals(actual.accessKey(), expected.accessKey());
        assertArrayEquals(actual.encryptionKey(), expected.encryptionKey());

    }
}
