//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signal.libsignal.internal.Native;

public class WebpSanitizerTest {
  @Before
  public void checkLibsignalMediaAvailable() {
    try {
      Native.SignalMedia_CheckAvailable();
    } catch (UnsatisfiedLinkError e) {
      Assume.assumeNoException(e);
    }
  }

  @Test
  public void testEmptyWebp() {
    byte[] data = new byte[] {};
    assertThrows(
        "empty webp accepted",
        ParseException.class,
        () -> WebpSanitizer.sanitize(new ByteArrayInputStream(data)));
  }

  @Test
  public void testTruncatedWebp() {
    byte[] data = new byte[] {0, 0, 0, 0};
    assertThrows(
        "truncated webp accepted",
        ParseException.class,
        () -> WebpSanitizer.sanitize(new ByteArrayInputStream(data)));
  }

  @Test
  public void testMinimalWebp() throws Exception {
    byte[] data = webp();
    WebpSanitizer.sanitize(new ByteArrayInputStream(data));
  }

  @Test
  public void testWebpIoError() throws Exception {
    try (InputStream ioErrorStream = new IoErrorInputStream()) {
      assertThrows(
          "InputStream exception not propagated",
          IOException.class,
          () -> WebpSanitizer.sanitize(ioErrorStream));
    }
  }

  private static byte[] webp() throws IOException {
    ByteArrayOutputStream webpOutputStream = new ByteArrayOutputStream();
    DataOutputStream webpDataOutputStream = new DataOutputStream(webpOutputStream);

    webpDataOutputStream.write("RIFF".getBytes()); // chunk type
    webpDataOutputStream.write(new byte[] {20, 0, 0, 0}); // chunk size
    webpDataOutputStream.write("WEBP".getBytes()); // webp header

    webpDataOutputStream.write("VP8L".getBytes()); // chunk type
    webpDataOutputStream.write(new byte[] {8, 0, 0, 0}); // chunk size
    webpDataOutputStream.write(
        new byte[] {0x2f, 0, 0, 0, 0, (byte) 0x88, (byte) 0x88, 8}); // VP8L data

    return webpOutputStream.toByteArray();
  }

  private static class IoErrorInputStream extends InputStream {
    @Override
    public int read() throws IOException {
      throw new IOException("test io error");
    }
  }
}
