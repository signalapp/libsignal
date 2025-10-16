//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/* eslint @typescript-eslint/no-shadow: ["error", { "allow": ["hash"] }] */

import { randomBytes } from 'node:crypto';
import { RANDOM_LENGTH } from './zkgroup/internal/Constants.js';
import * as Native from './Native.js';

export type UsernameLink = {
  entropy: Uint8Array;
  encryptedUsername: Uint8Array;
};

export function generateCandidates(
  nickname: string,
  minNicknameLength: number,
  maxNicknameLength: number
): string[] {
  return Native.Username_CandidatesFrom(
    nickname,
    minNicknameLength,
    maxNicknameLength
  );
}

export function fromParts(
  nickname: string,
  discriminator: string,
  minNicknameLength: number,
  maxNicknameLength: number
): { username: string; hash: Uint8Array } {
  const hash = Native.Username_HashFromParts(
    nickname,
    discriminator,
    minNicknameLength,
    maxNicknameLength
  );
  // If we generated the hash correctly, we can format the nickname and discriminator manually.
  const username = `${nickname}.${discriminator}`;
  return { username, hash };
}

export function hash(username: string): Uint8Array {
  return Native.Username_Hash(username);
}

export function generateProof(username: string): Uint8Array {
  const random = randomBytes(RANDOM_LENGTH);
  return generateProofWithRandom(username, random);
}

export function generateProofWithRandom(
  username: string,
  random: Uint8Array
): Uint8Array {
  return Native.Username_Proof(username, random);
}

export function decryptUsernameLink(usernameLink: UsernameLink): string {
  return Native.UsernameLink_DecryptUsername(
    usernameLink.entropy,
    usernameLink.encryptedUsername
  );
}

export function createUsernameLink(
  username: string,
  previousEntropy?: Uint8Array
): UsernameLink {
  const usernameLinkData = Native.UsernameLink_Create(
    username,
    previousEntropy ?? null
  );
  const entropy = usernameLinkData.subarray(0, 32);
  const encryptedUsername = usernameLinkData.subarray(32);
  return { entropy, encryptedUsername };
}

// Only for testing. Will throw on failure.
export function verifyProof(proof: Uint8Array, hash: Uint8Array): void {
  Native.Username_Verify(proof, hash);
}
