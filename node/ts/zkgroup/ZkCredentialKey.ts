//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { randomBytes } from 'node:crypto';

import * as Native from '../Native.js';
import ByteArray from './internal/ByteArray.js';
import { RANDOM_LENGTH } from './internal/Constants.js';

/**
 * A long-term Ristretto ZK credential key pair owned by an account.
 *
 * Distinct from the account's curve25519 identity key. Used as a binding identity across ZK
 * credentials issued to the account (currently the avatar upload credential).
 *
 * The secret half must be persisted by the account holder and synced to linked devices. The
 * public half is uploaded to the server.
 */
export class ZkCredentialKeyPair extends ByteArray {
  private readonly __type?: never;

  static generate(): ZkCredentialKeyPair {
    const random = randomBytes(RANDOM_LENGTH);

    return ZkCredentialKeyPair.generateWithRandom(random);
  }

  static generateWithRandom(
    random: Uint8Array<ArrayBuffer>
  ): ZkCredentialKeyPair {
    return new ZkCredentialKeyPair(
      Native.ZkCredentialKeyPair_GenerateDeterministic(random)
    );
  }

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.ZkCredentialKeyPair_CheckValidContents);
  }

  getPublicKey(): ZkCredentialPublicKey {
    return new ZkCredentialPublicKey(
      Native.ZkCredentialKeyPair_GetPublicKey(this.contents)
    );
  }
}

/** The public half of a {@link ZkCredentialKeyPair}. */
export class ZkCredentialPublicKey extends ByteArray {
  private readonly __type?: never;

  constructor(contents: Uint8Array<ArrayBuffer>) {
    super(contents, Native.ZkCredentialPublicKey_CheckValidContents);
  }
}
