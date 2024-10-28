//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.messagebackup;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.Test;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.kdf.HKDF;
import org.signal.libsignal.protocol.util.ByteUtil;
import org.signal.libsignal.util.ResourceReader;

public class MessageBackupValidationTest {

  static MessageBackupKey makeMessageBackupKey() {
    String accountEntropy = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
    Aci aci = new Aci(new UUID(0x1111111111111111L, 0x1111111111111111L));
    return new MessageBackupKey(accountEntropy, aci);
  }

  static MessageBackupKey makeMessageBackupKeyFromBackupId() {
    String accountEntropy = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
    Aci aci = new Aci(new UUID(0x1111111111111111L, 0x1111111111111111L));

    byte[] backupKey =
        HKDF.deriveSecrets(
            accountEntropy.getBytes(StandardCharsets.UTF_8),
            "20240801_SIGNAL_BACKUP_KEY".getBytes(StandardCharsets.UTF_8),
            32);
    byte[] backupId =
        HKDF.deriveSecrets(
            backupKey,
            ByteUtil.combine(
                "20241024_SIGNAL_BACKUP_ID:".getBytes(StandardCharsets.UTF_8),
                aci.toServiceIdBinary()),
            16);
    try {
      return new MessageBackupKey(new BackupKey(backupKey), backupId);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  static final String VALID_BACKUP_RESOURCE_NAME = "encryptedbackup.binproto.encrypted";
  static final MessageBackup.Purpose BACKUP_PURPOSE = MessageBackup.Purpose.REMOTE_BACKUP;

  @Test
  public void validBackupFile() throws IOException, ValidationError {
    Supplier<InputStream> factory =
        () -> {
          return MessageBackupValidationTest.class.getResourceAsStream(VALID_BACKUP_RESOURCE_NAME);
        };
    final long length;
    try (InputStream input = factory.get()) {
      length = ResourceReader.readAll(input).length;
    }
    MessageBackupKey key = makeMessageBackupKey();
    MessageBackup.ValidationResult result =
        MessageBackup.validate(key, BACKUP_PURPOSE, factory, length);
    assertArrayEquals(result.unknownFieldMessages, new String[0]);

    // Verify that the key can also be created from a backup ID and produce the same result.
    MessageBackupKey keyFromBackupId = makeMessageBackupKeyFromBackupId();
    MessageBackup.ValidationResult result2 =
        MessageBackup.validate(keyFromBackupId, BACKUP_PURPOSE, factory, length);
    assertArrayEquals(result2.unknownFieldMessages, new String[0]);
  }

  @Test
  public void messageBackupKeyPartsSmokeTest() {
    MessageBackupKey key = makeMessageBackupKey();
    // Just check some basic expectations.
    byte[] hmacKey = key.getHmacKey();
    byte[] aesKey = key.getAesKey();
    assertEquals(32, hmacKey.length);
    assertEquals(32, aesKey.length);
    assertFalse(Arrays.equals(hmacKey, aesKey));
  }

  @Test
  public void emptyBackupFile() {
    Supplier<InputStream> factory =
        () -> {
          return new ByteArrayInputStream(new byte[] {});
        };
    MessageBackupKey key = makeMessageBackupKey();

    ValidationError error =
        assertThrows(
            ValidationError.class,
            () -> {
              MessageBackup.validate(key, BACKUP_PURPOSE, factory, 0);
            });
    assertEquals(error.getMessage(), "not enough bytes for an HMAC");
  }

  @Test
  public void throwingInputStreamThrowsIoException() throws IOException {
    Supplier<InputStream> factory =
        () -> {
          return MessageBackupValidationTest.class.getResourceAsStream(VALID_BACKUP_RESOURCE_NAME);
        };
    final long length;
    try (InputStream input = factory.get()) {
      length = ResourceReader.getLength(input);
    }

    final long READABLE_BYTES = 60;
    assertTrue(READABLE_BYTES < length);

    Supplier<InputStream> throwingStreamFactory =
        () -> {
          return new ThrowingInputStream(factory.get(), READABLE_BYTES);
        };

    MessageBackupKey key = makeMessageBackupKey();
    IOException thrown =
        assertThrows(
            IOException.class,
            () -> {
              MessageBackup.validate(key, BACKUP_PURPOSE, throwingStreamFactory, length);
            });
    assertEquals(thrown.getMessage(), ThrowingInputStream.MESSAGE);
  }
}

/** Input stream that throws an exception after producing some number of bytes. */
class ThrowingInputStream extends InputStream {
  public static String MESSAGE = "exhausted read count";

  public ThrowingInputStream(InputStream inner, long bytesToReadBeforeThrowing) {
    this.inner = inner;
    this.bytesToReadBeforeThrowing = bytesToReadBeforeThrowing;
  }

  @Override
  public int read() throws IOException {
    checkBytesToReadBeforeThrowing();
    int b = this.inner.read();
    if (0 <= b && b <= 255) {
      this.bytesToReadBeforeThrowing--;
    }
    return b;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    checkBytesToReadBeforeThrowing();
    if (len > bytesToReadBeforeThrowing) {
      len = (int) bytesToReadBeforeThrowing;
    }
    int count = this.inner.read(b, off, len);
    this.bytesToReadBeforeThrowing -= count;
    return count;
  }

  private void checkBytesToReadBeforeThrowing() throws IOException {
    if (this.bytesToReadBeforeThrowing <= 0) {
      throw new IOException(ThrowingInputStream.MESSAGE);
    }
  }

  private InputStream inner;
  private long bytesToReadBeforeThrowing;
}
