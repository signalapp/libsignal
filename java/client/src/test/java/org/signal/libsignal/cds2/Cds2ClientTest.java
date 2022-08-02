//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.cds2;

import junit.framework.TestCase;
import org.signal.libsignal.protocol.util.Hex;

import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class Cds2ClientTest extends TestCase {
    private static final Instant EARLIEST_VALID_INSTANT = Instant.ofEpochMilli(1655857680000L);
    private byte[] mrenclave;
    private byte[] attestationMsg;
    protected void setUp() throws Exception {
        super.setUp();

        mrenclave = Hex.fromStringCondensed("39d78f17f8aa9a8e9cdaf16595947a057bac21f014d1abfd6a99b2dfd4e18d1d");

        // Test data should be ~14k
        attestationMsg = new byte[15_000];

        try (InputStream stream = getClass().getResourceAsStream("clienthandshakestart.data")) {
            assert stream != null;
            int read = stream.read(attestationMsg);
            // should be empty
            assert(stream.read() == -1);
            attestationMsg = Arrays.copyOf(attestationMsg, read);
        }
    }

    public void testCreateClient() throws AttestationDataException {
        Cds2Client cds2Client = new Cds2Client(mrenclave, attestationMsg, EARLIEST_VALID_INSTANT);
        byte[] initialMessage = cds2Client.initialRequest();
        assertEquals(48, initialMessage.length);
    }

    public void testCreateClientFailsWithInvalidMrenclave() {
        byte[]  invalidMrenclave = new byte[]{};
        try {
            new Cds2Client(invalidMrenclave, attestationMsg, EARLIEST_VALID_INSTANT);
        } catch (AttestationDataException e) {
            return;
        }
        fail();
    }

    public void testCreateClientFailsWithInvalidMessage() {
        byte[] invalidMessage = new byte[0];
        try {
            new Cds2Client(mrenclave, invalidMessage, EARLIEST_VALID_INSTANT);
        } catch (AttestationDataException e) {
            return;
        }
        fail();
    }

    public void testCreateClientFailsWithInvalidNonEmptyMessage() {
        byte[] invalidMessage = new byte[]{ 1 };
        try {
            new Cds2Client(mrenclave, invalidMessage, EARLIEST_VALID_INSTANT);
        } catch (AttestationDataException e) {
            return;
        }
        fail();
    }

    public void testEstablishedSendFailsPriorToEstablishment() throws AttestationDataException {
        Cds2Client cds2Client = new Cds2Client(mrenclave, attestationMsg, EARLIEST_VALID_INSTANT);
        try {
            cds2Client.establishedSend(new byte[]{1, 2, 3});
        } catch (IllegalStateException e) {
            return;
        } catch (Cds2CommunicationFailureException e) {
            fail();
        }
        fail();
    }

    public void testEstablishedRecvFailsPriorToEstablishment() throws AttestationDataException {
        Cds2Client cds2Client = new Cds2Client(mrenclave, attestationMsg, EARLIEST_VALID_INSTANT);
        try {
            cds2Client.establishedRecv(new byte[]{1, 2, 3});
        } catch (IllegalStateException e) {
            return;
        } catch (Cds2CommunicationFailureException e) {
            fail();
        }
        fail();
    }
}
