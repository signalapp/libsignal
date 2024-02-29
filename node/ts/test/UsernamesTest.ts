//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, expect } from 'chai';
import { ErrorCode, LibSignalError, LibSignalErrorBase } from '../Errors';
import * as usernames from '../usernames';
import * as util from './util';
import { decryptUsernameLink } from '../usernames';

util.initLogger();

function assertThrowsLibSignalError(
  expression: () => void,
  code: ErrorCode,
  message?: string
) {
  try {
    expression();
    assert.fail(message);
  } catch (e) {
    assert.instanceOf(e, Error, message);
    assert.instanceOf(e, LibSignalErrorBase, message);
    const err = e as LibSignalError;
    assert.equal(err.code, code, message);
  }
}

describe('usernames', () => {
  describe('hash', () => {
    it('can hash valid usernames', () => {
      assert.isNotEmpty(usernames.hash('He110.01'));
      assert.isNotEmpty(usernames.hash('usr.999999999'));
      assert.isNotEmpty(usernames.hash('_identifier.42'));
    });

    it('throws on invalid usernames', () => {
      assert.throws(() => usernames.hash('0zerostart.42'));
      assert.throws(() => usernames.hash('no_discriminator'));
      assert.throws(() => usernames.hash('🦀.42'));
      assert.throws(() => usernames.hash('s p a c e s.01'));
      assert.throws(() => usernames.hash('zero.00'));
      assert.throws(() => usernames.hash('zeropad.001'));
      assert.throws(() => usernames.hash('short.1'));
      assert.throws(() => usernames.hash('short_zero.0'));
    });
  });

  describe('proof verification', () => {
    it('works', () => {
      const nickname = 'He110.101';
      const hash = usernames.hash(nickname);
      const proof = usernames.generateProof(nickname);
      usernames.verifyProof(proof, hash);
    });

    it('does not allow interchanging proofs', () => {
      const hash = usernames.hash('He110.101');
      const proof = usernames.generateProof('sneaky.99');
      assert.throws(() => usernames.verifyProof(proof, hash));
    });

    it('throws for an invalid hash', () => {
      const nickname = 'He110.101';
      const hash = usernames.hash(nickname);
      const badHash = hash.slice(1);
      const proof = usernames.generateProof(nickname);
      assert.throws(() => usernames.verifyProof(proof, badHash));
    });
  });

  describe('fromParts', () => {
    it('can assemble valid usernames', () => {
      assert.equal(
        'jimio.01',
        usernames.fromParts('jimio', '01', 3, 32).username
      );
      const uint64Max = 2n ** 64n - 1n;
      assert.equal(
        `jimio.${uint64Max}`,
        usernames.fromParts('jimio', `${uint64Max}`, 3, 32).username
      );
    });

    it('generates valid hashes', () => {
      const { username, hash } = usernames.fromParts('jimio', '01', 3, 32);
      const proof = usernames.generateProof(username);
      usernames.verifyProof(proof, hash);
    });

    it('produces the correct error for invalid usernames', () => {
      assertThrowsLibSignalError(
        () => usernames.fromParts('', '01', 3, 32),
        ErrorCode.NicknameCannotBeEmpty
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('1digit', '01', 3, 32),
        ErrorCode.CannotStartWithDigit
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('s p a c e s', '01', 3, 32),
        ErrorCode.BadNicknameCharacter
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('abcde', '01', 10, 32),
        ErrorCode.NicknameTooShort
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('abcde', '01', 3, 4),
        ErrorCode.NicknameTooLong
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('jimio', '', 3, 32),
        ErrorCode.DiscriminatorCannotBeEmpty
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('jimio', '00', 3, 32),
        ErrorCode.DiscriminatorCannotBeZero
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('jimio', '012', 3, 32),
        ErrorCode.DiscriminatorCannotHaveLeadingZeros
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('jimio', '+12', 3, 32),
        ErrorCode.BadDiscriminatorCharacter
      );
      assertThrowsLibSignalError(
        () => usernames.fromParts('jimio', `${2n ** 64n}`, 3, 32),
        ErrorCode.DiscriminatorTooLarge
      );
    });
  });

  describe('generateCandidates', () => {
    it('can generate valid usernames', () => {
      const nickname = '_SiGNA1';
      const candidates = usernames.generateCandidates(nickname, 3, 32);
      assert.isNotEmpty(candidates);
      for (const candidate of candidates) {
        assert(
          candidate.startsWith(nickname),
          `${candidate} didn't start with ${nickname}`
        );
        const hash = usernames.hash(candidate);
        assert.isNotEmpty(hash);
        const proof = usernames.generateProof(candidate);
        assert.isNotEmpty(proof);
        usernames.verifyProof(proof, hash);
      }
    });

    it('will error on invalid nicknames', () => {
      expect(() => usernames.generateCandidates('ab', 3, 32))
        .throws(LibSignalErrorBase)
        .with.property('code', ErrorCode.NicknameTooShort);
      expect(() => usernames.generateCandidates('ab', 1, 32)).does.not.throw();
      expect(() => usernames.generateCandidates('abc', 1, 2))
        .throws(LibSignalErrorBase)
        .with.property('code', ErrorCode.NicknameTooLong);
      expect(() => usernames.generateCandidates('Ke$ha', 3, 32))
        .throws(LibSignalErrorBase)
        .with.property('code', ErrorCode.BadNicknameCharacter);
    });
  });

  describe('link', () => {
    it('works end to end with valid data', () => {
      const expectedUsername = 'signal_test.42';
      const usernameLinkData = usernames.createUsernameLink(expectedUsername);
      const actualUsername = decryptUsernameLink({
        entropy: usernameLinkData.entropy,
        encryptedUsername: usernameLinkData.encryptedUsername,
      });
      assert.equal(expectedUsername, actualUsername);
    });
    it('can reuse entropy', () => {
      const expectedUsername = 'signal_test.42';
      const usernameLinkData = usernames.createUsernameLink(expectedUsername);
      const actualUsername = decryptUsernameLink({
        entropy: usernameLinkData.entropy,
        encryptedUsername: usernameLinkData.encryptedUsername,
      });
      assert.equal(expectedUsername, actualUsername);

      const newLinkData = usernames.createUsernameLink(
        expectedUsername,
        usernameLinkData.entropy
      );
      assert.deepEqual(usernameLinkData.entropy, newLinkData.entropy);
      assert.notDeepEqual(
        usernameLinkData.encryptedUsername,
        newLinkData.encryptedUsername
      );
      const newActualUsername = decryptUsernameLink({
        entropy: newLinkData.entropy,
        encryptedUsername: newLinkData.encryptedUsername,
      });
      assert.equal(expectedUsername, newActualUsername);
    });
    it('will error on too long input data', () => {
      const longUsername = 'a'.repeat(128);
      expect(() => usernames.createUsernameLink(longUsername))
        .throws(LibSignalErrorBase)
        .with.property('code', ErrorCode.InputDataTooLong);
    });
    it('will error on invalid entropy data size', () => {
      const entropy = Buffer.alloc(16);
      const encryptedUsername = Buffer.alloc(32);
      expect(() => decryptUsernameLink({ entropy, encryptedUsername }))
        .throws(LibSignalErrorBase)
        .with.property('code', ErrorCode.InvalidEntropyDataLength);
    });
    it('will error on invalid encrypted username data', () => {
      const entropy = Buffer.alloc(32);
      const encryptedUsername = Buffer.alloc(32);
      expect(() => decryptUsernameLink({ entropy, encryptedUsername }))
        .throws(LibSignalErrorBase)
        .with.property('code', ErrorCode.InvalidUsernameLinkEncryptedData);
    });
  });
});
