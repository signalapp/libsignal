//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.media;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.Assert;
import org.junit.Test;

public class GuaranteedSkipInputStreamTest {
  private static class CallCountingInputStream extends FilterInputStream {
    int reads = 0;
    int skips = 0;

    CallCountingInputStream(InputStream in) {
      super(in);
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
      reads += 1;
      return super.read(buffer, offset, length);
    }

    @Override
    public long skip(long amount) throws IOException {
      skips += 1;
      return super.skip(amount);
    }
  }

  @Test
  public void normalInputStream() throws Exception {
    CallCountingInputStream innerStream =
        new CallCountingInputStream(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    stream.skip(5000);
    Assert.assertEquals(4000, stream.available());
    // Implementation details:
    Assert.assertEquals(1, innerStream.skips);
    Assert.assertEquals(0, innerStream.reads);
  }

  private static class SkiplessInputStream extends CallCountingInputStream {
    SkiplessInputStream(InputStream in) {
      super(in);
    }

    @Override
    public long skip(long amount) throws IOException {
      return 0;
    }
  }

  @Test
  public void skiplessInputStream() throws Exception {
    CallCountingInputStream innerStream =
        new SkiplessInputStream(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    stream.skip(5000);
    Assert.assertEquals(4000, stream.available());
    // Implementation details:
    Assert.assertEquals(0, innerStream.skips);
    Assert.assertEquals(3, innerStream.reads);
  }

  private static class SkiplessInputStreamWithSlowRead extends CallCountingInputStream {
    SkiplessInputStreamWithSlowRead(InputStream in) {
      super(in);
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
      return super.read(buffer, offset, Math.min(length, 16));
    }

    @Override
    public long skip(long amount) throws IOException {
      return 0;
    }
  }

  @Test
  public void skiplessInputStreamWithSlowRead() throws Exception {
    CallCountingInputStream innerStream =
        new SkiplessInputStreamWithSlowRead(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    stream.skip(5000);
    Assert.assertEquals(4000, stream.available());
    // Implementation details:
    Assert.assertEquals(0, innerStream.skips);
    Assert.assertEquals((int) Math.ceil(5000 / 16.0), innerStream.reads);
  }

  private static class LimitedSkipInputStream extends CallCountingInputStream {
    LimitedSkipInputStream(InputStream in) {
      super(in);
    }

    @Override
    public long skip(long amount) throws IOException {
      return super.skip(Math.min(amount, 16));
    }
  }

  @Test
  public void limitedSkip() throws Exception {
    CallCountingInputStream innerStream =
        new LimitedSkipInputStream(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    stream.skip(5000);
    Assert.assertEquals(4000, stream.available());
    // Implementation details:
    Assert.assertEquals((int) Math.ceil(5000 / 16.0), innerStream.skips);
    Assert.assertEquals(0, innerStream.reads);
  }

  private static class SkipUpTo1000InputStream extends CallCountingInputStream {
    final int fullLength;

    SkipUpTo1000InputStream(InputStream in) throws IOException {
      super(in);
      fullLength = available();
    }

    @Override
    public long skip(long amount) throws IOException {
      int consumed = fullLength - available();
      amount = Math.min(1000 - consumed, amount);
      if (amount <= 0) {
        return 0;
      }
      return super.skip(amount);
    }
  }

  @Test
  public void skipStopsWorking() throws Exception {
    CallCountingInputStream innerStream =
        new SkipUpTo1000InputStream(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    stream.skip(5000);
    Assert.assertEquals(4000, stream.available());
    // Implementation details:
    Assert.assertEquals(1, innerStream.skips);
    Assert.assertEquals(2, innerStream.reads);
  }

  private static class SkipThrowsExceptionInputStream extends FilterInputStream {
    IOException expectedException = new IOException();

    SkipThrowsExceptionInputStream(InputStream in) {
      super(in);
    }

    @Override
    public long skip(long amount) throws IOException {
      throw expectedException;
    }
  }

  @Test
  public void skipThrowsAnException() throws Exception {
    SkipThrowsExceptionInputStream innerStream =
        new SkipThrowsExceptionInputStream(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    IOException thrown = Assert.assertThrows(IOException.class, () -> stream.skip(5000));
    Assert.assertSame(innerStream.expectedException, thrown);
  }

  @Test
  public void nonPositiveSkipShortCircuits() throws Exception {
    SkipThrowsExceptionInputStream innerStream =
        new SkipThrowsExceptionInputStream(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    Assert.assertEquals(0, stream.skip(0));
    Assert.assertEquals(0, stream.skip(-1));
    Assert.assertEquals(0, stream.skip(-1000));
  }

  private static class ReadThrowsExceptionInputStream extends FilterInputStream {
    IOException expectedException = new IOException();

    ReadThrowsExceptionInputStream(InputStream in) {
      super(in);
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
      throw expectedException;
    }

    @Override
    public long skip(long amount) throws IOException {
      return 0;
    }
  }

  @Test
  public void readThrowsAnException() throws Exception {
    ReadThrowsExceptionInputStream innerStream =
        new ReadThrowsExceptionInputStream(new ByteArrayInputStream(new byte[9000]));
    InputStream stream = new GuaranteedSkipInputStream(innerStream);
    IOException thrown = Assert.assertThrows(IOException.class, () -> stream.skip(5000));
    Assert.assertSame(innerStream.expectedException, thrown);
  }

  @Test
  public void makeTrustedDoesNotDoSoRedundantly() throws Exception {
    InputStream base = new ByteArrayInputStream(new byte[9000]);
    InputStream trustedSkipStream = TrustedSkipInputStream.makeTrusted(base);
    Assert.assertNotSame(base, trustedSkipStream);
    InputStream trustedAgain = TrustedSkipInputStream.makeTrusted(trustedSkipStream);
    Assert.assertSame(trustedSkipStream, trustedAgain);
  }
}
