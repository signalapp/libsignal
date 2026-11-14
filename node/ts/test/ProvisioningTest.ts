//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert, expect } from 'chai';

import { ErrorCode, LibSignalErrorBase } from '../Errors.js';
import * as Provisioning from '../Provisioning.js';
import * as util from './util.js';

util.initLogger();

/** Asserts that `fn` throws a {@link LibSignalErrorBase} with the given code */
function assertThrowsCode(fn: () => unknown, code: ErrorCode): void {
  expect(fn).to.throw(LibSignalErrorBase).with.property('code', code);
}

describe('Provisioning', () => {
  it('round-trips a provision message', () => {
    const secondary = Provisioning.RecvProvisionCiphertextState.generate();
    const pubkeyBytes = secondary.publicKey.serialize();
    assert.lengthOf(pubkeyBytes, 33);
    assert.equal(pubkeyBytes[0], 0x05);

    const message = new TextEncoder().encode('provision message');
    const envelope = Provisioning.encryptProvisionMessage(
      Provisioning.ProvisioningPublicKey.deserialize(pubkeyBytes),
      message
    );
    assert.deepEqual(secondary.decryptEnvelope(envelope), message);
  });

  it('rejects an envelope for a different recipient', () => {
    const secondary = Provisioning.RecvProvisionCiphertextState.generate();
    const other = Provisioning.RecvProvisionCiphertextState.generate();
    const envelope = Provisioning.encryptProvisionMessage(
      secondary.publicKey,
      Uint8Array.of(1, 2, 3)
    );
    assertThrowsCode(
      () => other.decryptEnvelope(envelope),
      ErrorCode.InvalidProvisioningMessage
    );
  });

  it('rejects malformed envelopes', () => {
    const secondary = Provisioning.RecvProvisionCiphertextState.generate();
    assertThrowsCode(
      () => secondary.decryptEnvelope(Uint8Array.of(0xff)),
      ErrorCode.InvalidProvisioningMessage
    );
    assertThrowsCode(
      () => secondary.decryptEnvelope(new Uint8Array()),
      ErrorCode.InvalidProvisioningMessage
    );
  });

  it('rejects bad public keys', () => {
    const pubkeyBytes =
      Provisioning.RecvProvisionCiphertextState.generate().publicKey.serialize();
    const badVersion = Uint8Array.from(pubkeyBytes);
    badVersion[0] = 0x06;
    for (const badKey of [
      pubkeyBytes.subarray(0, 32),
      Uint8Array.of(...pubkeyBytes, 0),
      badVersion,
    ]) {
      assertThrowsCode(
        () =>
          Provisioning.encryptProvisionMessage(
            Provisioning.ProvisioningPublicKey.deserialize(badKey),
            new Uint8Array()
          ),
        ErrorCode.Generic
      );
    }
  });
});
