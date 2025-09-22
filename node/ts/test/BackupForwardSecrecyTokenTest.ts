//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, expect } from 'chai';
import { BackupForwardSecrecyToken } from '../AccountKeys.js';

describe('BackupForwardSecrecyToken', () => {
  it('can create a valid token and retrieve same bytes', () => {
    const validBytes = new Uint8Array(32).fill(0x42);
    const token = new BackupForwardSecrecyToken(validBytes);

    assert.exists(token);
    assert.equal(token.serialize().length, 32);

    const retrievedBytes = token.serialize();
    expect(retrievedBytes).to.deep.equal(validBytes);
  });

  it('throws on invalid token creation - too short', () => {
    const invalidBytes = new Uint8Array(31).fill(0x42);
    assert.throws(
      () => new BackupForwardSecrecyToken(invalidBytes),
      'Length of array supplied was 31 expected 32'
    );
  });

  it('throws on invalid token creation - too long', () => {
    const invalidBytes = new Uint8Array(33).fill(0x42);
    assert.throws(
      () => new BackupForwardSecrecyToken(invalidBytes),
      'Length of array supplied was 33 expected 32'
    );
  });

  it('supports round-trip serialization', () => {
    // Use different hardcoded pattern to ensure we're not just getting lucky
    const originalBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      originalBytes[i] = i % 256;
    }

    const token = new BackupForwardSecrecyToken(originalBytes);

    // Serialize and deserialize
    const serialized = token.serialize();
    const reconstructedToken = new BackupForwardSecrecyToken(serialized);

    assert.exists(reconstructedToken);
    assert.equal(reconstructedToken.serialize().length, 32);

    const reconstructedBytes = reconstructedToken.serialize();
    expect(reconstructedBytes).to.deep.equal(originalBytes);
  });

  it('has correct SIZE constant', () => {
    assert.equal(BackupForwardSecrecyToken.SIZE, 32);
  });
});
