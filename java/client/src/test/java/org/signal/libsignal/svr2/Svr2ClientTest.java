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
        final byte[] mrenclave = Hex.fromStringCondensed("f25dfd3b18adc4c0dc190bae1edd603ceca81b42a10b1de52f74db99b338619e");
        final Instant instant = Instant.ofEpochSecond(1676529724);

        final byte[] pin = "password".getBytes(StandardCharsets.UTF_8);
        final byte[] username = "username".getBytes(StandardCharsets.UTF_8);
        final long groupId = 3862621253427332054L;

        final Svr2Client svr2Client = Svr2Client.create_NOT_FOR_PRODUCTION(mrenclave, svr2Handshake, instant);
        Assert.assertEquals(48, svr2Client.initialRequest().length);
        final PinHash actual = svr2Client.hashPin(pin, username);

        final byte[] expectedSalt = HKDF.deriveSecrets(username, bebytes(groupId), new byte[]{}, 32);
        final byte[] knownSalt = Hex.fromStringCondensed("d6159ba30f90b6eb6ccf1ec844427f052baaf0705da849767471744cdb3f8a5e");
        Assert.assertArrayEquals(knownSalt, expectedSalt);

        final PinHash expected = PinHash.create(pin, expectedSalt);
        Assert.assertArrayEquals(actual.accessKey(), expected.accessKey());
        Assert.assertArrayEquals(actual.encryptionKey(), expected.encryptionKey());

    }
}
