//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { assert } from 'chai';
import {
  Recipient,
  default as SealedSenderMultiRecipientMessage,
} from '../SealedSenderMultiRecipientMessage';
import * as util from './util';

util.initLogger();

function bufferFromHexStrings(...input: string[]): Buffer {
  return Buffer.concat(input.map((s) => Buffer.from(s, 'hex')));
}

const VERSION_ACI_ONLY = '22';
const VERSION_SERVICE_ID_AWARE = '23';
const VERSION_RECIPIENT_MESSAGE = '22';

const ACI_MARKER = '00';
const PNI_MARKER = '01';

const ALICE_UUID = '9d0652a3-dcc3-4d11-975f-74d61598733f';
const ALICE_UUID_BYTES = '9d0652a3dcc34d11975f74d61598733f';
const ALICE_KEY_MATERIAL =
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const BOB_UUID = 'e80f7bbe-5b94-471e-bd8c-2173654ea3d1';
const BOB_UUID_BYTES = 'e80f7bbe5b94471ebd8c2173654ea3d1';
const BOB_KEY_MATERIAL =
  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

const EVE_UUID = '3f0f4734-e331-4434-bd4f-6d8f6ea6dcc7';
const EVE_UUID_BYTES = '3f0f4734e3314434bd4f6d8f6ea6dcc7';

const MALLORY_UUID = '5d088142-6fd7-4dbd-af00-fdda1b3ce988';
const MALLORY_UUID_BYTES = '5d0881426fd74dbdaf00fdda1b3ce988';

const SHARED_BYTES =
  '99999999999999999999999999999999999999999999999999999999999999999999';

function assertMessageForRecipient(
  message: SealedSenderMultiRecipientMessage,
  recipient: Recipient,
  ...expectedHexParts: string[]
): void {
  const expected = bufferFromHexStrings(...expectedHexParts);
  assert.deepEqual(
    message.messageForRecipient(recipient).toString('hex'),
    expected.toString('hex')
  );
}

describe('SealedSenderMultiRecipientMessage', () => {
  it('can parse simple ACI-only messages', () => {
    const input = bufferFromHexStrings(
      VERSION_ACI_ONLY,
      // Count
      '03',
      // Recipient 1: UUID, Device ID and Registration ID, Key Material
      ALICE_UUID_BYTES,
      '0111aa',
      ALICE_KEY_MATERIAL,
      // Recipient 2
      BOB_UUID_BYTES,
      '0111bb',
      BOB_KEY_MATERIAL,
      // Recipient 3 (note that it's another device of Bob's)
      BOB_UUID_BYTES,
      '0333bb',
      BOB_KEY_MATERIAL,
      // Shared data
      SHARED_BYTES
    );

    const message = new SealedSenderMultiRecipientMessage(input);
    assert.deepEqual(
      Object.getOwnPropertyNames(message.recipientsByServiceIdString()),
      [ALICE_UUID, BOB_UUID]
    );

    const alice = message.recipientsByServiceIdString()[ALICE_UUID];
    assert.isNotNull(alice);
    assert.deepEqual(alice.deviceIds, [0x01]);
    assert.deepEqual(alice.registrationIds, [0x11aa]);
    assertMessageForRecipient(
      message,
      alice,
      VERSION_RECIPIENT_MESSAGE,
      ALICE_KEY_MATERIAL,
      SHARED_BYTES
    );

    const bob = message.recipientsByServiceIdString()[BOB_UUID];
    assert.isNotNull(bob);
    assert.deepEqual(bob.deviceIds, [0x01, 0x03]);
    assert.deepEqual(bob.registrationIds, [0x11bb, 0x33bb]);
    assertMessageForRecipient(
      message,
      bob,
      VERSION_RECIPIENT_MESSAGE,
      BOB_KEY_MATERIAL,
      SHARED_BYTES
    );
  });

  it('can parse ServiceId-based messages with compact device lists', () => {
    const input = bufferFromHexStrings(
      VERSION_SERVICE_ID_AWARE,
      // Count
      '02',
      // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
      ACI_MARKER,
      ALICE_UUID_BYTES,
      '0111aa',
      ALICE_KEY_MATERIAL,
      // Recipient 2
      PNI_MARKER,
      BOB_UUID_BYTES,
      '0191bb', // high bit in registration ID flags another device
      '0333bb',
      BOB_KEY_MATERIAL,
      // Shared data
      SHARED_BYTES
    );

    const message = new SealedSenderMultiRecipientMessage(input);
    assert.deepEqual(
      Object.getOwnPropertyNames(message.recipientsByServiceIdString()),
      [ALICE_UUID, `PNI:${BOB_UUID}`]
    );

    const alice = message.recipientsByServiceIdString()[ALICE_UUID];
    assert.isNotNull(alice);
    assert.deepEqual(alice.deviceIds, [0x01]);
    assert.deepEqual(alice.registrationIds, [0x11aa]);
    assertMessageForRecipient(
      message,
      alice,
      VERSION_RECIPIENT_MESSAGE,
      ALICE_KEY_MATERIAL,
      SHARED_BYTES
    );

    const bob = message.recipientsByServiceIdString()[`PNI:${BOB_UUID}`];
    assert.isNotNull(bob);
    assert.deepEqual(bob.deviceIds, [0x01, 0x03]);
    assert.deepEqual(bob.registrationIds, [0x11bb, 0x33bb]);
    assertMessageForRecipient(
      message,
      bob,
      VERSION_RECIPIENT_MESSAGE,
      BOB_KEY_MATERIAL,
      SHARED_BYTES
    );
  });

  it('can handle excluded recipients', () => {
    const input = bufferFromHexStrings(
      VERSION_SERVICE_ID_AWARE,
      // Count
      '04',
      // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
      ACI_MARKER,
      ALICE_UUID_BYTES,
      '0191aa', // high bit in registration ID flags another device
      '0333aa',
      ALICE_KEY_MATERIAL,
      // Recipient 2: excluded by device ID 0
      ACI_MARKER,
      EVE_UUID_BYTES,
      '00',
      // Recipient 3
      PNI_MARKER,
      BOB_UUID_BYTES,
      '0111bb',
      BOB_KEY_MATERIAL,
      // Recipient 4 (also excluded)
      ACI_MARKER,
      MALLORY_UUID_BYTES,
      '00',
      // Shared data
      SHARED_BYTES
    );

    const message = new SealedSenderMultiRecipientMessage(input);
    assert.deepEqual(
      Object.getOwnPropertyNames(message.recipientsByServiceIdString()),
      [ALICE_UUID, `PNI:${BOB_UUID}`]
    );

    const alice = message.recipientsByServiceIdString()[ALICE_UUID];
    assert.isNotNull(alice);
    assert.deepEqual(alice.deviceIds, [0x01, 0x03]);
    assert.deepEqual(alice.registrationIds, [0x11aa, 0x33aa]);
    assertMessageForRecipient(
      message,
      alice,
      VERSION_RECIPIENT_MESSAGE,
      ALICE_KEY_MATERIAL,
      SHARED_BYTES
    );

    const bob = message.recipientsByServiceIdString()[`PNI:${BOB_UUID}`];
    assert.isNotNull(bob);
    assert.deepEqual(bob.deviceIds, [0x01]);
    assert.deepEqual(bob.registrationIds, [0x11bb]);
    assertMessageForRecipient(
      message,
      bob,
      VERSION_RECIPIENT_MESSAGE,
      BOB_KEY_MATERIAL,
      SHARED_BYTES
    );

    assert.deepEqual(message.excludedRecipientServiceIdStrings(), [
      EVE_UUID,
      MALLORY_UUID,
    ]);
  });

  it('rejects repeated excluded recipients', () => {
    const input = bufferFromHexStrings(
      VERSION_SERVICE_ID_AWARE,
      // Count
      '03',
      // Recipient 1: ServiceId, Device ID and Registration ID, Key Material
      ACI_MARKER,
      ALICE_UUID_BYTES,
      '0191aa', // high bit in registration ID flags another device
      '0333aa',
      ALICE_KEY_MATERIAL,
      // Recipient 2: excluded by device ID 0
      ACI_MARKER,
      EVE_UUID_BYTES,
      '00',
      // Recipient 3 (same as #2)
      ACI_MARKER,
      EVE_UUID_BYTES,
      '00',
      // Shared data
      SHARED_BYTES
    );

    assert.throws(() => new SealedSenderMultiRecipientMessage(input));
  });

  it('rejects unknown versions', () => {
    assert.throws(() => new SealedSenderMultiRecipientMessage(Buffer.of(0x11)));
    assert.throws(() => new SealedSenderMultiRecipientMessage(Buffer.of(0x2f)));
    assert.throws(() => new SealedSenderMultiRecipientMessage(Buffer.of(0x77)));
  });
});
