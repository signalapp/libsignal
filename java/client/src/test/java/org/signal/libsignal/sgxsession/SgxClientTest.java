//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.sgxsession;

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.signal.libsignal.attest.AttestationDataException;
import org.signal.libsignal.attest.AttestationFailedException;
import org.signal.libsignal.cds2.Cds2Client;
import org.signal.libsignal.svr2.Svr2Client;
import org.signal.libsignal.util.ResourceReader;

@RunWith(Parameterized.class)
public class SgxClientTest {

  static enum ServiceType {
    SVR2,
    CDS2
  }

  private byte[] mrenclave;
  private byte[] attestationMsg;
  private Instant validInstant;
  private ServiceType serviceType;
  private int initialMessageSize;

  public SgxClientTest(
      byte[] mrenclave,
      byte[] attestationMsg,
      Instant earliestValidInstant,
      ServiceType serviceType,
      int initialMessageSize) {
    this.mrenclave = mrenclave;
    this.attestationMsg = attestationMsg;
    this.validInstant = earliestValidInstant;
    this.serviceType = serviceType;
    this.initialMessageSize = initialMessageSize;
  }

  @Parameters(name = "{3}")
  public static Collection<Object[]> data() throws Exception {
    byte[] cds2Handshake =
        ResourceReader.readAll(SgxClientTest.class.getResourceAsStream("cdsi.handshakestart"));
    byte[] svr2Handshake =
        ResourceReader.readAll(SgxClientTest.class.getResourceAsStream("svr2.handshakestart"));
    return Arrays.asList(
        new Object[][] {
          {
            ResourceReader.readAll(SgxClientTest.class.getResourceAsStream("cdsi.mrenclave")),
            cds2Handshake,
            Instant.ofEpochSecond(
                ByteBuffer.wrap(
                        ResourceReader.readAll(
                            SgxClientTest.class.getResourceAsStream("cdsi.timestamp")))
                    .getLong()),
            ServiceType.CDS2,
            1632
          },
          {
            ResourceReader.readAll(SgxClientTest.class.getResourceAsStream("svr2.mrenclave")),
            svr2Handshake,
            Instant.ofEpochSecond(
                ByteBuffer.wrap(
                        ResourceReader.readAll(
                            SgxClientTest.class.getResourceAsStream("svr2.timestamp")))
                    .getLong()),
            ServiceType.SVR2,
            1632
          }
        });
  }

  private SgxClient getClient(byte[] mrenclave, byte[] attestationMsg, Instant currentTime)
      throws AttestationDataException, AttestationFailedException {
    switch (serviceType) {
      case SVR2:
        return new Svr2Client(mrenclave, attestationMsg, currentTime);
      case CDS2:
        return new Cds2Client(mrenclave, attestationMsg, currentTime);
    }
    throw new IllegalStateException();
  }

  @Test
  public void testCreateClient() throws AttestationDataException, AttestationFailedException {
    SgxClient client = getClient(mrenclave, attestationMsg, validInstant);
    byte[] initialMessage = client.initialRequest();
    assertEquals(this.initialMessageSize, initialMessage.length);
  }

  @Test(expected = AttestationDataException.class)
  public void testCreateClientFailsWithInvalidMrenclave()
      throws AttestationDataException, AttestationFailedException {
    byte[] invalidMrenclave = new byte[] {};
    getClient(invalidMrenclave, attestationMsg, validInstant);
  }

  @Test(expected = AttestationDataException.class)
  public void testCreateClientFailsWithInvalidMessage()
      throws AttestationDataException, AttestationFailedException {
    byte[] invalidMessage = new byte[0];
    getClient(mrenclave, invalidMessage, validInstant);
  }

  @Test(expected = AttestationDataException.class)
  public void testCreateClientFailsWithInvalidNonEmptyMessage()
      throws AttestationDataException, AttestationFailedException {
    byte[] invalidMessage = new byte[] {1};
    getClient(mrenclave, invalidMessage, validInstant);
  }

  @Test(expected = IllegalStateException.class)
  public void testEstablishedSendFailsPriorToEstablishment()
      throws AttestationDataException,
          AttestationFailedException,
          SgxCommunicationFailureException {
    SgxClient client = getClient(mrenclave, attestationMsg, validInstant);
    client.establishedSend(new byte[] {1, 2, 3});
  }

  @Test(expected = IllegalStateException.class)
  public void testEstablishedRecvFailsPriorToEstablishment()
      throws AttestationDataException,
          AttestationFailedException,
          SgxCommunicationFailureException {
    SgxClient client = getClient(mrenclave, attestationMsg, validInstant);
    client.establishedRecv(new byte[] {1, 2, 3});
  }
}
