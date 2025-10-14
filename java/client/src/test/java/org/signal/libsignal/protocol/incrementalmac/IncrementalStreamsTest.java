//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.protocol.incrementalmac;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.signal.libsignal.protocol.util.Hex;
import org.signal.libsignal.util.ResourceReader;

@RunWith(Parameterized.class)
public class IncrementalStreamsTest {
  private static final byte[] TEST_HMAC_KEY =
      Hex.fromStringCondensedAssert(
          "a83481457efecc69ad1342e21d9c0297f71debbf5c9304b4c1b2e433c1a78f98");
  private static final String TEST_EXPECTED_DIGEST =
      "84892f70600e549fb72879667a9d96a273f144b698ff9ef5a76062a56061a909ac028f107e1306e1ec8d17c989fa3430d88d7b294d00828a65a2acb3efa31a1f";
  private static final int CHUNK_SIZE = 32;
  private static final ChunkSizeChoice SIZE_CHOICE = ChunkSizeChoice.everyNthByte(CHUNK_SIZE);
  private static final String[] TEST_INPUT_PARTS = {
    "this is a test", " input to the incremental ", "mac stream 👋"
  };
  private static final byte[] TEST_INPUT_BYTES;

  static {
    TEST_INPUT_BYTES = String.join("", TEST_INPUT_PARTS).getBytes();
  }

  @Parameter public boolean useDirectBuffer;

  @Parameters
  public static Collection<Boolean> data() {
    return Arrays.asList(Boolean.TRUE, Boolean.FALSE);
  }

  @Test
  public void testDigestCreation() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] actualDigest = fullIncrementalDigest(out, TEST_INPUT_PARTS);
    assertEquals(String.join("", TEST_INPUT_PARTS), out.toString());
    assertEquals(TEST_EXPECTED_DIGEST, Hex.toStringCondensed(actualDigest));
  }

  @Test
  public void testValidationSuccessByteByByte() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);

    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(TEST_INPUT_BYTES, digest)) {
      int inputLength = TEST_INPUT_BYTES.length;
      byte[] output = new byte[inputLength];
      int pos = 0;
      while (true) {
        int b = incrementalIn.read();
        if (b == -1) {
          break;
        }
        output[pos++] = (byte) b;
      }
      assertArrayEquals(TEST_INPUT_BYTES, output);
    }
  }

  @Test
  public void testValidationSuccessShortInnerReads() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);

    var channel =
        new ReadableByteChannel() {
          private final ByteArrayInputStream in = new ByteArrayInputStream(TEST_INPUT_BYTES);
          // Will either return zero or less-then-chunk bytes from read
          private boolean readNothing = false;

          @Override
          public boolean isOpen() {
            return true;
          }

          @Override
          public void close() throws IOException {
            this.in.close();
          }

          @Override
          public int read(ByteBuffer dst) throws IOException {
            int toRead = Math.min(this.readNothing ? 0 : (CHUNK_SIZE / 3), dst.remaining());
            this.readNothing = !this.readNothing;
            byte[] buffer = new byte[toRead];
            int actuallyRead = this.in.read(buffer);
            if (actuallyRead > 0) {
              dst.put(buffer, 0, actuallyRead);
            }
            return actuallyRead;
          }
        };

    try (IncrementalMacInputStream incrementalIn = makeIncrementalInputStream(channel, digest)) {
      int totalRead = validateFully(incrementalIn, 1024);
      assertEquals(TEST_INPUT_BYTES.length, totalRead);
    }
  }

  @Test
  public void testValidationSuccessSmallBuffer() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);

    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(TEST_INPUT_BYTES, digest)) {
      int totalRead = validateFully(incrementalIn, CHUNK_SIZE / 3);
      assertEquals(TEST_INPUT_BYTES.length, totalRead);
    }
  }

  @Test
  public void testValidationSuccessLargeBuffer() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    byte[] largeBuffer = new byte[1024];

    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(TEST_INPUT_BYTES, digest)) {
      // Even though the buffer allows it, we get one chunk at a time.
      assertEquals(CHUNK_SIZE, readSomeBytes(largeBuffer, incrementalIn));
      assertEquals(TEST_INPUT_BYTES.length - CHUNK_SIZE, readSomeBytes(largeBuffer, incrementalIn));
    }
  }

  @Test
  public void testValidationFailure() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    byte[] corruptInput = TEST_INPUT_BYTES.clone();
    // Introduce the error in the second chunk
    corruptInput[CHUNK_SIZE + 2] ^= (byte) 0xff;
    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(corruptInput, digest)) {
      byte[] buffer = new byte[CHUNK_SIZE];
      // first chunk should read fine
      readSomeBytes(buffer, incrementalIn);
      assertThrows(InvalidMacException.class, () -> readSomeBytes(buffer, incrementalIn));
    }
  }

  @Test
  public void testNoDataIsReadWithoutValidation() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    byte[] corruptInput = TEST_INPUT_BYTES.clone();
    corruptInput[1] ^= (byte) 0xff;
    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(corruptInput, digest)) {
      assertThrows(
          InvalidMacException.class,
          () -> {
            // Should through even though the corruption is in the second byte
            incrementalIn.read();
          });
    }
  }

  @Test
  public void testReadsShouldAlwaysFailFollowingValidationSuccess() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);

    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(TEST_INPUT_BYTES, digest)) {
      int totalRead = validateFully(incrementalIn, CHUNK_SIZE / 3);
      assertEquals(TEST_INPUT_BYTES.length, totalRead);

      assertEquals(-1, incrementalIn.read());
    }
  }

  @Test
  public void testValidationEmptyInput() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(new byte[0], digest)) {
      byte[] read = ResourceReader.readAll(incrementalIn);
      assertEquals(0, read.length);
    }
  }

  @Test
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

  @Test
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

  @Test
  public void testInputStreamCloseIsIdempotent() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);

    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(TEST_INPUT_BYTES, digest)) {
      int totalRead = validateFully(incrementalIn, CHUNK_SIZE / 3);
      assertEquals(TEST_INPUT_BYTES.length, totalRead);
      // This call is redundant but that is _exactly_ what this test is testing
      incrementalIn.close();
    }
  }

  @Test
  public void testDigestEmptyInput() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream digest = new ByteArrayOutputStream();
    try (IncrementalMacOutputStream incrementalOut =
        new IncrementalMacOutputStream(
            out, TEST_HMAC_KEY, ChunkSizeChoice.inferChunkSize(0), digest)) {
      incrementalOut.write(new byte[0]);
      incrementalOut.flush();
    }
  }

  @Test
  public void testValidationReadBounds() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(TEST_INPUT_BYTES, digest)) {
      try {
        int _ignored = incrementalIn.read(new byte[10], 5, 10);
        fail("Bounds check should have thrown");
      } catch (IllegalArgumentException ex) {
        // Expected
      }
    }
  }

  @Test
  public void testValidationReadAfterClose() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), TEST_INPUT_PARTS);
    IncrementalMacInputStream incrementalIn = makeIncrementalInputStream(TEST_INPUT_BYTES, digest);
    incrementalIn.close();
    try {
      int _ignored = incrementalIn.read();
    } catch (IOException ex) {
      // Expected
    }
  }

  @Test
  public void testInvalidChunkSize() {
    var ex =
        assertThrows(
            AssertionError.class,
            () ->
                new IncrementalMacOutputStream(
                    new ByteArrayOutputStream(),
                    TEST_HMAC_KEY,
                    ChunkSizeChoice.everyNthByte(0),
                    new ByteArrayOutputStream()));
    assertTrue(ex.getMessage().contains("chunk size must be positive"));
  }

  @Test
  public void testInvalidDigestList() {
    assertThrows(
        InvalidMacException.class, () -> makeIncrementalInputStream(new byte[0], new byte[1]));
  }

  @Test
  public void testEmptyInput() throws IOException {
    byte[] digest = fullIncrementalDigest(new ByteArrayOutputStream(), new String[0]);
    try (IncrementalMacInputStream incrementalIn =
        makeIncrementalInputStream(new byte[0], digest)) {
      int totalRead = validateFully(incrementalIn, 13);
      assertEquals(0, totalRead);
    }
  }

  private static byte[] fullIncrementalDigest(OutputStream innerOut, String[] input)
      throws IOException {
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

  /** Calls the {@link InputStream#read(byte[])}} continuously while it returns 0. */
  private static int readSomeBytes(byte[] dst, InputStream src) throws IOException {
    int bytesRead = 0;
    while (bytesRead == 0) {
      bytesRead = src.read(dst);
    }
    return bytesRead;
  }

  private static int validateFully(IncrementalMacInputStream in, int bufferSize)
      throws IOException {
    byte[] buffer = new byte[bufferSize];
    int totalBytesRead = 0;
    int bytesRead = 0;
    while (bytesRead != -1) {
      totalBytesRead += bytesRead;
      bytesRead = in.read(buffer);
    }
    return totalBytesRead;
  }

  private IncrementalMacInputStream makeIncrementalInputStream(
      ReadableByteChannel channel, byte[] digest) throws InvalidMacException {
    return new IncrementalMacInputStream(
        channel, TEST_HMAC_KEY, SIZE_CHOICE, digest, this.useDirectBuffer);
  }

  private IncrementalMacInputStream makeIncrementalInputStream(
      ByteArrayInputStream in, byte[] digest) throws InvalidMacException {
    return makeIncrementalInputStream(Channels.newChannel(in), digest);
  }

  private IncrementalMacInputStream makeIncrementalInputStream(byte[] input, byte[] digest)
      throws InvalidMacException {
    return makeIncrementalInputStream(new ByteArrayInputStream(input), digest);
  }
}
