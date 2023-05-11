//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
package org.signal.libsignal.svr2;

import org.junit.Assert;
import org.junit.Test;
import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.protocol.kdf.HKDF;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.sgxsession.SgxClientTest;
import org.signal.libsignal.util.ResourceReader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class Svr2ClientTest {

    private static byte[] bebytes(final long l) {
        final ByteBuffer bb = ByteBuffer.allocate(8);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putLong(l);
        return bb.array();
    }

    @Test
    public void testSaltWithGroupId() throws IOException, AttestationDataException {
        final byte[] svr2Handshake = ResourceReader.readAll(SgxClientTest.class.getResourceAsStream("svr2handshakestart.data"));
        final byte[] mrenclave = Hex.fromStringCondensed("a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95");
        final Instant instant = Instant.ofEpochSecond(1683836600);

        final byte[] pin = "password".getBytes(StandardCharsets.UTF_8);
        final byte[] username = "username".getBytes(StandardCharsets.UTF_8);
        final long groupId = Long.parseUnsignedLong("15525669046665930652");

        final Svr2Client svr2Client = Svr2Client.create(mrenclave, svr2Handshake, instant);
        Assert.assertEquals(48, svr2Client.initialRequest().length);
        final PinHash actual = svr2Client.hashPin(pin, username);

        final byte[] expectedSalt = HKDF.deriveSecrets(username, bebytes(groupId), new byte[]{}, 32);
        final byte[] knownSalt = Hex.fromStringCondensed("260d1f6d233c9326e8ba744e778b7b127147c7211d9bc3219ab3b7394766c508");
        Assert.assertArrayEquals(knownSalt, expectedSalt);

        final PinHash expected = PinHash.create(pin, expectedSalt);
        Assert.assertArrayEquals(actual.accessKey(), expected.accessKey());
        Assert.assertArrayEquals(actual.encryptionKey(), expected.encryptionKey());

    }
}
