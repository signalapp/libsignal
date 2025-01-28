//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.usernames;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Test;
import org.signal.libsignal.protocol.util.Hex;

public class UsernamesTest {
  @Test
  public void testUsernameGeneration() throws BaseUsernameException {
    String nickname = "SiGNAl";
    List<Username> usernames = Username.candidatesFrom(nickname, 3, 32);
    assertFalse("Non-zero number of usernames expected", usernames.size() == 0);
    for (Username name : usernames) {
      assertTrue(
          String.format("%s does not start with %s", name, nickname),
          name.getUsername().startsWith(nickname));
    }
  }

  @Test
  public void testInvalidNicknameValidation() throws BaseUsernameException {
    List<String> invalidNicknames =
        List.of(
            "hi",
            "way_too_long_to_be_a_reasonable_nickname",
            "I⍰Unicode",
            "s p a c e s",
            "0zerostart");
    for (String nickname : invalidNicknames) {
      try {
        Username.candidatesFrom(nickname, 3, 32);
        fail(String.format("'%s' should not be considered valid", nickname));
      } catch (BaseUsernameException ex) {
        // this is fine
      }
    }
  }

  @Test
  public void testValidUsernameHashing() throws BaseUsernameException {
    String username = "he110.42";
    byte[] hash = new Username(username).getHash();
    assertEquals(32, hash.length);
    assertEquals(
        "f63f0521eb3adfe1d936f4b626b89558483507fbdb838fc554af059111cf322e",
        Hex.toStringCondensed(hash));
  }

  @Test
  public void testToTheProofAndBack() throws BaseUsernameException {
    Username username = new Username("hello_signal.42");
    assertNotNull(username.getHash());
    byte[] proof = username.generateProof();
    assertNotNull(proof);
    assertEquals(128, proof.length);
    Username.verifyProof(proof, username.getHash());
  }

  @Test
  public void testInvalidHash() throws BaseUsernameException {
    Username username = new Username("hello_signal.42");
    byte[] proof = username.generateProof();

    SecureRandom r = new SecureRandom();
    byte[] badHash = new byte[32];
    r.nextBytes(badHash);

    try {
      Username.verifyProof(proof, badHash);
    } catch (BaseUsernameException ex) {
      assertTrue(ex.getMessage().contains("Username could not be verified"));
    }
  }

  @Test
  public void testInvalidRandomness() throws BaseUsernameException {
    try {
      new Username("valid_name.01").generateProofWithRandomness(new byte[31]);
    } catch (IllegalArgumentException err) {
      assertThat(err.getMessage(), containsString("expected array with length 32"));
    }
  }

  @Test
  public void testInvalidUsernames() throws BaseUsernameException {
    List<String> usernames = List.of("0zerostart.01", "zero.00", "short_zero.0", "short_one.1");
    for (String name : usernames) {
      try {
        new Username(name);
        fail(String.format("'%s' should not be valid", name));
      } catch (BaseUsernameException ex) {
        // this is fine
      }
    }
    for (String name : usernames) {
      try {
        new Username(name).generateProof();
        fail(String.format("'%s' should not be valid", name));
      } catch (BaseUsernameException ex) {
        // this is fine
      }
    }
  }

  @Test
  public void testValidUsernamesFromParts() throws BaseUsernameException {
    Username jimio01 = Username.fromParts("jimio", "01", 3, 32);
    assertEquals("jimio.01", jimio01.getUsername());
    byte[] proof = jimio01.generateProof();
    Username.verifyProof(proof, jimio01.getHash());

    // Try a discriminator that Java can't represent directly.
    String uint64Max = "18446744073709551615";
    assertEquals("jimio." + uint64Max, Username.fromParts("jimio", uint64Max, 3, 32).getUsername());
  }

  @Test
  public void testCorrectExceptionForInvalidUsernamesFromParts() throws BaseUsernameException {
    assertThrows(CannotBeEmptyException.class, () -> Username.fromParts("", "01", 3, 32));
    assertThrows(
        CannotStartWithDigitException.class, () -> Username.fromParts("1digit", "01", 3, 32));
    assertThrows(
        BadNicknameCharacterException.class, () -> Username.fromParts("s p a c e s", "01", 3, 32));
    assertThrows(NicknameTooShortException.class, () -> Username.fromParts("abcde", "01", 10, 32));
    assertThrows(NicknameTooLongException.class, () -> Username.fromParts("abcde", "01", 3, 4));
    assertThrows(
        DiscriminatorCannotBeEmptyException.class, () -> Username.fromParts("jimio", "", 3, 32));
    assertThrows(
        DiscriminatorCannotBeZeroException.class, () -> Username.fromParts("jimio", "00", 3, 32));
    assertThrows(
        BadDiscriminatorCharacterException.class, () -> Username.fromParts("jimio", "+12", 3, 32));
    assertThrows(
        DiscriminatorTooLargeException.class,
        () -> Username.fromParts("jimio", "18446744073709551616", 3, 32));
  }

  @Test
  public void testUsernameLinkHappyCase() throws BaseUsernameException {
    final Username expectedUsername = new Username("hello_signal.42");
    final Username.UsernameLink link = expectedUsername.generateLink();
    final Username actualUsername = Username.fromLink(link);
    assertEquals(expectedUsername.getUsername(), actualUsername.getUsername());
  }

  @Test
  public void testUsernameLinkReusedEntropy() throws BaseUsernameException {
    final Username expectedUsername = new Username("hello_signal.42");
    final Username.UsernameLink link = expectedUsername.generateLink();
    final Username actualUsername = Username.fromLink(link);
    assertEquals(expectedUsername.getUsername(), actualUsername.getUsername());

    final Username.UsernameLink newLink = expectedUsername.generateLink(link.getEntropy());
    assertArrayEquals(link.getEntropy(), newLink.getEntropy());
    assertFalse(Arrays.equals(link.getEncryptedUsername(), newLink.getEncryptedUsername()));
    final Username newActualUsername = Username.fromLink(newLink);
    assertEquals(expectedUsername.getUsername(), newActualUsername.getUsername());
  }

  @Test
  public void testCreateLinkFailsForLongUsername() throws BaseUsernameException {
    final String longUsername = Stream.generate(() -> "a").limit(128).collect(Collectors.joining());
    try {
      new Username(longUsername).generateLink();
      fail("Expected to fail creating a link for a long username");
    } catch (BaseUsernameException ex) {
      // this is fine
    }
  }

  @Test
  public void testDecryptUsernameFromLinkFailsForInvalidEntropySize() throws BaseUsernameException {
    final byte[] entropy = new byte[16];
    final byte[] encryptedUsername = new byte[32];
    try {
      Username.fromLink(new Username.UsernameLink(entropy, encryptedUsername));
      fail("Expected to fail decrypting username link with an invalid entropy size");
    } catch (BaseUsernameException ex) {
      // this is fine
    }
  }

  @Test
  public void testDecryptUsernameFromLinkFailsForInvalidEncryptedUsername()
      throws BaseUsernameException {
    final byte[] entropy = new byte[32];
    final byte[] encryptedUsername = new byte[32];
    try {
      Username.fromLink(new Username.UsernameLink(entropy, encryptedUsername));
      fail("Expected to fail decrypting username link with an invalid link data");
    } catch (BaseUsernameException ex) {
      // this is fine
    }
  }
}
