//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import { RANDOM_LENGTH } from '../internal/Constants';
import NativeImpl from '../../NativeImpl';

import UuidCiphertext from './UuidCiphertext';

import ProfileKeyCiphertext from './ProfileKeyCiphertext';
import ProfileKey from '../profiles/ProfileKey';
import GroupSecretParams from './GroupSecretParams';
import { UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';
import { SignalClientErrorBase } from '../../Errors';

export default class ClientZkGroupCipher {
  groupSecretParams: GroupSecretParams;

  constructor(groupSecretParams: GroupSecretParams) {
    this.groupSecretParams = groupSecretParams;
  }

  encryptUuid(uuid: UUIDType): UuidCiphertext {
    return new UuidCiphertext(
      NativeImpl.GroupSecretParams_EncryptUuid(
        this.groupSecretParams.getContents(),
        fromUUID(uuid)
      )
    );
  }

  decryptUuid(uuidCiphertext: UuidCiphertext): UUIDType {
    return toUUID(
      NativeImpl.GroupSecretParams_DecryptUuid(
        this.groupSecretParams.getContents(),
        uuidCiphertext.getContents()
      )
    );
  }

  encryptProfileKey(
    profileKey: ProfileKey,
    uuid: UUIDType
  ): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(
      NativeImpl.GroupSecretParams_EncryptProfileKey(
        this.groupSecretParams.getContents(),
        profileKey.getContents(),
        fromUUID(uuid)
      )
    );
  }

  decryptProfileKey(
    profileKeyCiphertext: ProfileKeyCiphertext,
    uuid: UUIDType
  ): ProfileKey {
    return new ProfileKey(
      NativeImpl.GroupSecretParams_DecryptProfileKey(
        this.groupSecretParams.getContents(),
        profileKeyCiphertext.getContents(),
        fromUUID(uuid)
      )
    );
  }

  encryptBlob(plaintext: Buffer): Buffer {
    const random = randomBytes(RANDOM_LENGTH);

    return this.encryptBlobWithRandom(random, plaintext);
  }

  encryptBlobWithRandom(random: Buffer, plaintext: Buffer): Buffer {
    const paddedPlaintext = Buffer.alloc(plaintext.length + 4);
    plaintext.copy(paddedPlaintext, 4);
    return NativeImpl.GroupSecretParams_EncryptBlobDeterministic(
      this.groupSecretParams.getContents(),
      random,
      paddedPlaintext
    );
  }

  decryptBlob(blobCiphertext: Buffer): Buffer {
    const newContents = NativeImpl.GroupSecretParams_DecryptBlob(
      this.groupSecretParams.getContents(),
      blobCiphertext
    );

    if (newContents.length < 4) {
      throw new SignalClientErrorBase(
        'BAD LENGTH',
        'VerificationFailed',
        'decryptBlob'
      );
    }

    const padLen = newContents.readInt32BE(0);
    if (newContents.length < 4 + padLen) {
      throw new SignalClientErrorBase(
        'BAD LENGTH',
        'VerificationFailed',
        'decryptBlob'
      );
    }

    const depaddedContents = Buffer.alloc(newContents.length - (4 + padLen));
    newContents.copy(depaddedContents, 0, 4, newContents.length - padLen);

    return depaddedContents;
  }
}
