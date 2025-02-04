//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import static org.junit.Assert.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signal.libsignal.internal.Native;
import org.signal.libsignal.protocol.util.ByteUtil;

public class Mp4SanitizerTest {
  @Before
  public void checkLibsignalMediaAvailable() {
    try {
      Native.SignalMedia_CheckAvailable();
    } catch (UnsatisfiedLinkError e) {
      Assume.assumeNoException(e);
    }
  }

  @Test
  public void testEmptyMp4() {
    byte[] data = new byte[] {};
    assertThrows(
        "empty mp4 accepted",
        ParseException.class,
        () -> Mp4Sanitizer.sanitize(new ByteArrayInputStream(data), data.length));
  }

  @Test
  public void testTruncatedMp4() {
    byte[] data = new byte[] {0, 0, 0, 0};
    assertThrows(
        "truncated mp4 accepted",
        ParseException.class,
        () -> Mp4Sanitizer.sanitize(new ByteArrayInputStream(data), data.length));
  }

  @Test
  public void testNoopMinimalMp4() throws Exception {
    byte[] metadata = ByteUtil.combine(ftyp(), moov());
    byte[] mp4Data = ByteUtil.combine(metadata, mdat());

    SanitizedMetadata sanitized =
        Mp4Sanitizer.sanitize(new ByteArrayInputStream(mp4Data), mp4Data.length);

    assertSanitizedMetadataEquals(
        sanitized, metadata.length, mp4Data.length - metadata.length, null);
  }

  @Test
  public void testMinimalMp4() throws Exception {
    byte[] metadata = ByteUtil.combine(ftyp(), moov());
    byte[] mp4Data = ByteUtil.combine(ftyp(), mdat(), moov());

    SanitizedMetadata sanitized =
        Mp4Sanitizer.sanitize(new ByteArrayInputStream(mp4Data), mp4Data.length);

    assertSanitizedMetadataEquals(
        sanitized, ftyp().length, mp4Data.length - metadata.length, metadata);
  }

  @Test
  public void testMinimalCompoundedMdatMp4() throws Exception {
    byte[] metadata = ByteUtil.combine(ftyp(), moov());
    byte[] compounded_mdat = compoundedMdat();
    byte[] mp4Data = ByteUtil.combine(ftyp(), compounded_mdat, moov());

    SanitizedMetadata sanitized =
        Mp4Sanitizer.sanitizeFileWithCompoundedMdatBoxes(
            new ByteArrayInputStream(mp4Data), mp4Data.length, compounded_mdat.length);

    assertSanitizedMetadataEquals(
        sanitized, ftyp().length, mp4Data.length - metadata.length, metadata);
  }

  @Test
  public void testBrokenSkipWorkaround() throws Exception {
    // Same setup as testMinimalMp4.
    byte[] metadata = ByteUtil.combine(ftyp(), moov());
    byte[] mp4Data = ByteUtil.combine(ftyp(), mdat(), moov());

    SanitizedMetadata sanitized =
        Mp4Sanitizer.sanitize(
            new BrokenSkipInputStream(new ByteArrayInputStream(mp4Data)), mp4Data.length);

    assertSanitizedMetadataEquals(
        sanitized, ftyp().length, mp4Data.length - metadata.length, metadata);
  }

  @Test
  public void testMp4IoError() throws Exception {
    try (InputStream ioErrorStream = new IoErrorInputStream()) {
      assertThrows(
          "InputStream exception not propagated",
          IOException.class,
          () -> Mp4Sanitizer.sanitize(ioErrorStream, 1));
    }
  }

  private static byte[] ftyp() throws IOException {
    ByteArrayOutputStream ftypOutputStream = new ByteArrayOutputStream();
    DataOutputStream ftypDataOutputStream = new DataOutputStream(ftypOutputStream);

    ftypDataOutputStream.writeInt(20); // box size
    ftypDataOutputStream.write("ftyp".getBytes()); // box type
    ftypDataOutputStream.write("isom".getBytes()); // major_brand
    ftypDataOutputStream.writeInt(0); // minor_version
    ftypDataOutputStream.write("isom".getBytes()); // compatible_brands

    return ftypOutputStream.toByteArray();
  }

  private static byte[] moov() throws IOException {
    ByteArrayOutputStream moovOutputStream = new ByteArrayOutputStream();
    DataOutputStream moovDataOutputStream = new DataOutputStream(moovOutputStream);

    // moov box header
    moovDataOutputStream.writeInt(56); // box size
    moovDataOutputStream.write("moov".getBytes()); // box type

    // trak box (inside moov box)
    moovDataOutputStream.writeInt(48); // box size
    moovDataOutputStream.write("trak".getBytes()); // box type

    // mdia box (inside trak box)
    moovDataOutputStream.writeInt(40); // box size
    moovDataOutputStream.write("mdia".getBytes()); // box type

    // minf box (inside mdia box)
    moovDataOutputStream.writeInt(32); // box size
    moovDataOutputStream.write("minf".getBytes()); // box type

    // stbl box (inside minf box)
    moovDataOutputStream.writeInt(24); // box size
    moovDataOutputStream.write("stbl".getBytes()); // box type

    // stco box (inside stbl box)
    moovDataOutputStream.writeInt(16); // box size
    moovDataOutputStream.write("stco".getBytes()); // box type
    moovDataOutputStream.writeInt(0); // box version & flags
    moovDataOutputStream.writeInt(0); // entry count

    return moovOutputStream.toByteArray();
  }

  private static byte[] mdat() throws IOException {
    ByteArrayOutputStream mdatOutputStream = new ByteArrayOutputStream();
    DataOutputStream mdatDataOutputStream = new DataOutputStream(mdatOutputStream);

    mdatDataOutputStream.writeInt(16); // box size
    mdatDataOutputStream.write("mdat".getBytes()); // box type
    mdatDataOutputStream.write("12345678".getBytes()); // some fake contents

    return mdatOutputStream.toByteArray();
  }

  private static byte[] compoundedMdat() throws IOException {
    ByteArrayOutputStream mdatOutputStream = new ByteArrayOutputStream();
    DataOutputStream mdatDataOutputStream = new DataOutputStream(mdatOutputStream);

    mdatDataOutputStream.writeInt(0); // box size
    mdatDataOutputStream.write("mdat".getBytes()); // box type
    mdatDataOutputStream.write("12345678".getBytes()); // some fake contents

    return mdatOutputStream.toByteArray();
  }

  private static void assertSanitizedMetadataEquals(
      SanitizedMetadata sanitized, long dataOffset, long dataLength, byte[] metadata) {
    Assert.assertArrayEquals(sanitized.getSanitizedMetadata(), metadata);
    Assert.assertEquals(sanitized.getDataOffset(), dataOffset);
    Assert.assertEquals(sanitized.getDataLength(), dataLength);
  }

  private static class IoErrorInputStream extends InputStream {
    @Override
    public int read() throws IOException {
      throw new IOException("test io error");
    }
  }

  private static class BrokenSkipInputStream extends FilterInputStream {
    BrokenSkipInputStream(InputStream in) {
      super(in);
    }

    @Override
    public long skip(long amount) throws IOException {
      return 0;
    }
  }
}
