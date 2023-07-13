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
import { Aci, ServiceId } from '../../Address';

export default class ClientZkGroupCipher {
  groupSecretParams: GroupSecretParams;

  constructor(groupSecretParams: GroupSecretParams) {
    this.groupSecretParams = groupSecretParams;
  }

  encryptServiceId(serviceId: ServiceId): UuidCiphertext {
    return new UuidCiphertext(
      Native.GroupSecretParams_EncryptServiceId(
        this.groupSecretParams.getContents(),
        serviceId.getServiceIdFixedWidthBinary()
      )
    );
  }

  decryptServiceId(ciphertext: UuidCiphertext): ServiceId {
    return ServiceId.parseFromServiceIdFixedWidthBinary(
      Native.GroupSecretParams_DecryptServiceId(
        this.groupSecretParams.getContents(),
        ciphertext.getContents()
      )
    );
  }

  encryptProfileKey(profileKey: ProfileKey, userId: Aci): ProfileKeyCiphertext {
    return new ProfileKeyCiphertext(
      Native.GroupSecretParams_EncryptProfileKey(
        this.groupSecretParams.getContents(),
        profileKey.getContents(),
        userId.getServiceIdFixedWidthBinary()
      )
    );
  }

  decryptProfileKey(
    profileKeyCiphertext: ProfileKeyCiphertext,
    userId: Aci
  ): ProfileKey {
    return new ProfileKey(
      Native.GroupSecretParams_DecryptProfileKey(
        this.groupSecretParams.getContents(),
        profileKeyCiphertext.getContents(),
        userId.getServiceIdFixedWidthBinary()
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
