//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import junit.framework.TestCase;
import org.signal.libsignal.protocol.util.Hex;

public class IncrementalStreamsTest extends TestCase {
  private static final byte[] TEST_HMAC_KEY =
      Hex.fromStringCondensedAssert(
          "a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98");
  private static final String TEST_EXPECTED_DIGEST =
      "84892f70600e549fb72879667a9d96a273f144b698ff9ef5a76062a56061a909884f6d9f42918a9e476ed518c4ac8f714bd33f045152ae049877fd3d1b0db25a";
  private static final int CHUNK_SIZE = 32;
  private static final ChunkSizeChoice SIZE_CHOICE = ChunkSizeChoice.everyNthByte(CHUNK_SIZE);
  private static final String[] TEST_INPUT_PARTS = {
    "this is a test", " input to the incremental ", "mac stream"
  };

  public void testIncrementalDigestCreation() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] actualDigest = fullIncrementalDigest(out, TEST_INPUT_PARTS);
    assertEquals(String.join("", TEST_INPUT_PARTS), out.toString());
    assertEquals(TEST_EXPECTED_DIGEST, Hex.toStringCondensed(actualDigest));
  }

  public void testIncrementalValidationSuccess() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    ByteArrayInputStream in =
        new ByteArrayInputStream(String.join("", TEST_INPUT_PARTS).getBytes());

    try (IncrementalMacInputStream incrementalIn =
        new IncrementalMacInputStream(in, TEST_HMAC_KEY, SIZE_CHOICE, digest)) {
      byte[] buffer = new byte[CHUNK_SIZE / 3]; // intentionally small
      int totalBytesRead = 0;
      while (incrementalIn.read(buffer) != -1) {}
    }
  }

  public void testIncrementalValidationSuccessaByteByByte() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    ByteArrayInputStream in =
        new ByteArrayInputStream(String.join("", TEST_INPUT_PARTS).getBytes());

    try (IncrementalMacInputStream incrementalIn =
        new IncrementalMacInputStream(in, TEST_HMAC_KEY, SIZE_CHOICE, digest)) {
      while (incrementalIn.read() != -1) {}
    }
  }

  public void testIncrementalValidationOneShotRead() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    ByteArrayInputStream in =
        new ByteArrayInputStream(String.join("", TEST_INPUT_PARTS).getBytes());
    byte[] largeBuffer = new byte[1024];

    try (IncrementalMacInputStream incrementalIn =
        new IncrementalMacInputStream(in, TEST_HMAC_KEY, SIZE_CHOICE, digest)) {
      // Even though the buffer allows it, we get one chunk at a time.
      assertEquals(CHUNK_SIZE, incrementalIn.read(largeBuffer));
      assertEquals(18, incrementalIn.read(largeBuffer));
    }
  }

  public void testIncrementalValidationFailure() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    byte[] corruptInput = String.join("", TEST_INPUT_PARTS).getBytes();
    corruptInput[42] ^= 0xff;
    ByteArrayInputStream in = new ByteArrayInputStream(corruptInput);
    try (IncrementalMacInputStream incrementalIn =
        new IncrementalMacInputStream(in, TEST_HMAC_KEY, SIZE_CHOICE, digest)) {
      byte[] buffer = new byte[CHUNK_SIZE / 2];
      assertEquals(16, incrementalIn.read(buffer));
      assertEquals(16, incrementalIn.read(buffer));
      // by now we have read the first chunk, and the next read will fail
      try {
        incrementalIn.read(buffer);
        fail("The read should have failed");
      } catch (InvalidMacException _ex) {
      }
    }
  }

  public void testNoDataIsReadWithoutValidation() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    byte[] corruptInput = String.join("", TEST_INPUT_PARTS).getBytes();
    corruptInput[1] ^= 0xff;
    ByteArrayInputStream in = new ByteArrayInputStream(corruptInput);
    try (IncrementalMacInputStream incrementalIn =
        new IncrementalMacInputStream(in, TEST_HMAC_KEY, SIZE_CHOICE, digest)) {
      try {
        // even though the corruption is in the second byte
        incrementalIn.read();
        fail("The read should have failed");
      } catch (InvalidMacException _ex) {
      }
    }
  }

  public void testSingleByteRead() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {});
    try (IncrementalMacInputStream incrementalIn =
        new IncrementalMacInputStream(in, TEST_HMAC_KEY, SIZE_CHOICE, digest)) {
      int read = incrementalIn.read();
      assertEquals(-1, read);
    }
  }

  public void testMultipleFlushesWhileWriting() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream digestStream = new ByteArrayOutputStream();
    try (IncrementalMacOutputStream incrementalOut =
        new IncrementalMacOutputStream(out, TEST_HMAC_KEY, SIZE_CHOICE, digestStream)) {
      for (String part : TEST_INPUT_PARTS) {
        incrementalOut.write(part.getBytes());
        incrementalOut.flush();
      }
    }
    byte[] actualDigest = digestStream.toByteArray();
    assertEquals(TEST_EXPECTED_DIGEST, Hex.toStringCondensed(actualDigest));
  }

  public void testOutputStreamCloseIsIdempotent() throws IOException {
    ByteArrayOutputStream digestStream = new ByteArrayOutputStream();
    IncrementalMacOutputStream incrementalOut =
        new IncrementalMacOutputStream(
            new ByteArrayOutputStream(), TEST_HMAC_KEY, SIZE_CHOICE, digestStream);
    for (String part : TEST_INPUT_PARTS) {
      incrementalOut.write(part.getBytes());
    }
    incrementalOut.close();
    incrementalOut.close();

    assertEquals(TEST_EXPECTED_DIGEST, Hex.toStringCondensed(digestStream.toByteArray()));
  }

  public void testEmptyInput() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream digest = new ByteArrayOutputStream();
    try (IncrementalMacOutputStream incrementalOut =
        new IncrementalMacOutputStream(
            out, TEST_HMAC_KEY, ChunkSizeChoice.inferChunkSize(0), digest)) {
      incrementalOut.write(new byte[0]);
      incrementalOut.flush();
    }
  }

  public void testInvalidChunkSize() throws IOException {
    try {
      new IncrementalMacOutputStream(
          new ByteArrayOutputStream(),
          TEST_HMAC_KEY,
          ChunkSizeChoice.everyNthByte(0),
          new ByteArrayOutputStream());
    } catch (AssertionError ex) {
      assertTrue(ex.getMessage().contains("chunk size must be positive"));
    }
  }

  private byte[] fullIncrementalDigest(OutputStream innerOut, String[] input) throws IOException {
    ByteArrayOutputStream digestStream = new ByteArrayOutputStream();
    try (IncrementalMacOutputStream incrementalOut =
        new IncrementalMacOutputStream(innerOut, TEST_HMAC_KEY, SIZE_CHOICE, digestStream)) {
      for (String part : input) {
        incrementalOut.write(part.getBytes());
      }
      incrementalOut.flush();
    }
    return digestStream.toByteArray();
  }
}
