//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.cds2;

import junit.framework.TestCase;

import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class Cds2ClientTest extends TestCase {

    private static final byte[] MRENCLAVE = new byte[]{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1};
    private static final byte[] CA_CERT = new byte[]{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
    private byte[] attestationMsg;

    private static final Instant EARLIEST_VALID_INSTANT = Instant.now().minus(Duration.ofDays(1));

    protected void setUp() throws Exception {
        super.setUp();

        // Test data should be ~14k
        attestationMsg = new byte[15_000];

        try (InputStream stream = getClass().getResourceAsStream("clienthandshakestart.data")) {
            assert stream != null;

            int offset = 0;
            int read = stream.read(attestationMsg, offset, attestationMsg.length) - offset;

            // Make sure we don't need to bump up the static array size
            assert read < attestationMsg.length;

            attestationMsg = Arrays.copyOf(attestationMsg, read);
        }
    }

    public void testCreateClient() throws AttestationDataException {
        Cds2Client cds2Client = Cds2Client.create_NOT_FOR_PRODUCTION(MRENCLAVE, CA_CERT, attestationMsg, EARLIEST_VALID_INSTANT);
        byte[] initialMessage = cds2Client.initialRequest();
        assertEquals(48, initialMessage.length);
    }

    public void testCreateClientFailsWithInvalidMrenclave() {
        byte[]  invalidMrenclave = new byte[]{};
        try {
            Cds2Client.create_NOT_FOR_PRODUCTION(invalidMrenclave, CA_CERT, attestationMsg, EARLIEST_VALID_INSTANT);
        } catch (AttestationDataException e) {
            return;
        }
        fail();
    }

    public void testCreateClientFailsWithInvalidCert() {
        byte[] invalidCert = new byte[0];
        try {
            Cds2Client.create_NOT_FOR_PRODUCTION(MRENCLAVE, invalidCert, attestationMsg, EARLIEST_VALID_INSTANT);
        } catch (AttestationDataException e) {
            return;
        }
        fail();
    }

    public void testCreateClientFailsWithInvalidMessage() {
        byte[] invalidMessage = new byte[0];
        try {
            Cds2Client.create_NOT_FOR_PRODUCTION(MRENCLAVE, CA_CERT, invalidMessage, EARLIEST_VALID_INSTANT);
        } catch (AttestationDataException e) {
            return;
        }
        fail();
    }

    public void testCreateClientFailsWithInvalidNonEmptyMessage() {
        byte[] invalidMessage = new byte[]{ 1 };
        try {
            Cds2Client.create_NOT_FOR_PRODUCTION(MRENCLAVE, CA_CERT, invalidMessage, EARLIEST_VALID_INSTANT);
        } catch (AttestationDataException e) {
            return;
        }
        fail();
    }

    public void testEstablishedSendFailsPriorToEstablishment() throws AttestationDataException {
        Cds2Client cds2Client = Cds2Client.create_NOT_FOR_PRODUCTION(MRENCLAVE, CA_CERT, attestationMsg, EARLIEST_VALID_INSTANT);
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
        Cds2Client cds2Client = Cds2Client.create_NOT_FOR_PRODUCTION(MRENCLAVE, CA_CERT, attestationMsg, EARLIEST_VALID_INSTANT);
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
