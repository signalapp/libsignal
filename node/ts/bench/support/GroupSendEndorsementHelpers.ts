//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomUUID } from 'node:crypto';
import { Aci, ServiceId } from '../../Address';
import {
  ClientZkGroupCipher,
  GroupMasterKey,
  GroupSecretParams,
  GroupSendDerivedKeyPair,
  GroupSendEndorsementsResponse,
  ServerSecretParams,
} from '../../zkgroup';

const SECONDS_PER_DAY = 60 * 60 * 24;

export const serverSecretParams = ServerSecretParams.generate();
export const serverPublicParams = serverSecretParams.getPublicParams();

const masterKey = new GroupMasterKey(
  Buffer.from(
    '6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283',
    'hex'
  )
);
export const groupSecretParams =
  GroupSecretParams.deriveFromMasterKey(masterKey);

export const groupMembers: ServiceId[] = [];
for (let i = 0; i < 1000; ++i) {
  groupMembers.push(Aci.fromUuid(randomUUID()));
}

export const groupCiphertexts = groupMembers.map((next) =>
  new ClientZkGroupCipher(groupSecretParams).encryptServiceId(next)
);

// Server
const now = Math.floor(Date.now() / 1000);
const startOfDay = now - (now % SECONDS_PER_DAY);
const expiration = startOfDay + 2 * SECONDS_PER_DAY;
const todaysKey = GroupSendDerivedKeyPair.forExpiration(
  new Date(1000 * expiration),
  serverSecretParams
);
export const response = GroupSendEndorsementsResponse.issue(
  groupCiphertexts,
  todaysKey
);
