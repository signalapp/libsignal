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
import org.signal.libsignal.util.Base64;
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
  public void AccountEntropyPoolValidity() {
    assertFalse(AccountEntropyPool.isValid("invalid key"));
    assertTrue(
        AccountEntropyPool.isValid(
            "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"));
  }

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
  public void onlineValidation() throws IOException, ValidationError {
    final InputStream input = ComparableBackupTest.getCanonicalBackupInputStream();

    final int backupInfoLength = input.read();
    assertFalse("unexpected EOF", backupInfoLength == -1);
    assertTrue("single-byte varint", backupInfoLength < 0x80);
    final byte[] backupInfo = new byte[backupInfoLength];
    assertEquals("unexpected EOF", input.read(backupInfo), backupInfoLength);
    final OnlineBackupValidator backup = new OnlineBackupValidator(backupInfo, BACKUP_PURPOSE);

    int frameLength;
    while ((frameLength = input.read()) != -1) {
      // Tiny varint parser, only supports two bytes.
      if (frameLength >= 0x80) {
        final int secondByte = input.read();
        assertFalse("unexpected EOF", secondByte == -1);
        assertTrue("at most a two-byte varint", secondByte < 0x80);
        frameLength -= 0x80;
        frameLength |= secondByte << 7;
      }
      final byte[] frame = new byte[frameLength];
      assertEquals("unexpected EOF", input.read(frame), frameLength);
      backup.addFrame(frame);
    }

    backup.close();
  }

  @Test
  public void onlineValidatorRejectsInvalidBackupInfo() {
    assertThrows(
        ValidationError.class, () -> new OnlineBackupValidator(new byte[0], BACKUP_PURPOSE));
  }

  // The following payload was generated via protoscope.
  // % protoscope -s | base64
  // The fields are described by Backup.proto.
  //
  // 1: 1
  // 2: 1731715200000
  // 3: {`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`}
  private static byte[] VALID_BACKUP_INFO =
      Base64.decode("CAEQgOiTkrMyGiAAESIzRFVmd4iZqrvM3e7/ABEiM0RVZneImaq7zN3u/w==");

  @Test
  public void onlineValidatorRejectsInvalidFrame() throws ValidationError {
    final var backup = new OnlineBackupValidator(VALID_BACKUP_INFO, BACKUP_PURPOSE);
    assertThrows(ValidationError.class, () -> backup.addFrame(new byte[0]));
  }

  @Test
  public void onlineValidatorRejectsInvalidAtClose() throws ValidationError {
    final var backup = new OnlineBackupValidator(VALID_BACKUP_INFO, BACKUP_PURPOSE);
    assertThrows(ValidationError.class, () -> backup.close());
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
