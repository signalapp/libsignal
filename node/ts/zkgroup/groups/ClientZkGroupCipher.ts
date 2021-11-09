//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'crypto';
import { RANDOM_LENGTH } from '../internal/Constants';
import * as Native from '../../../Native';

import UuidCiphertext from './UuidCiphertext';

import ProfileKeyCiphertext from './ProfileKeyCiphertext';
import ProfileKey from '../profiles/ProfileKey';
import GroupSecretParams from './GroupSecretParams';
import { UUIDType, fromUUID, toUUID } from '../internal/UUIDUtil';

export default class ClientZkGroupCipher {
  groupSecretParams: GroupSecretParams;

  constructor(groupSecretParams: GroupSecretParams) {
    this.groupSecretParams = groupSecretParams;
  }

  encryptUuid(uuid: UUIDType): UuidCiphertext {
    return new UuidCiphertext(
      Native.GroupSecretParams_EncryptUuid(
        this.groupSecretParams.getContents(),
        fromUUID(uuid)
      )
    );
  }

  decryptUuid(uuidCiphertext: UuidCiphertext): UUIDType {
    return toUUID(
      Native.GroupSecretParams_DecryptUuid(
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
      Native.GroupSecretParams_EncryptProfileKey(
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
      Native.GroupSecretParams_DecryptProfileKey(
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
    return Native.GroupSecretParams_EncryptBlobWithPaddingDeterministic(
      this.groupSecretParams.getContents(),
      random,
      plaintext,
      0
    );
  }

  decryptBlob(blobCiphertext: Buffer): Buffer {
    return Native.GroupSecretParams_DecryptBlobWithPadding(
      this.groupSecretParams.getContents(),
      blobCiphertext
    );
  }
}
