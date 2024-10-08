//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/**
 * Cryptographic hashing, randomness generation, etc. related to SVR/Backup Keys.
 *
 * Currently only the Account Entropy Pool is exposed, because no other functionality is used on Desktop.
 *
 * @module Pin
 */

import * as Native from '../Native';

/**
 * The randomly-generated user-memorized entropy used to derive the backup key,
 *    with other possible future uses.
 *
 * Contains log_2(36^64) = ~330 bits of entropy.
 */
export class AccountEntropyPool {
  /**
   * Randomly generates an Account Entropy Pool and returns the cannonical string
   *  representation of that pool.
   *
   * @returns cryptographically random 64 character string of characters a-z, 0-9
   */
  public static generate(): string {
    return Native.AccountEntropyPool_Generate();
  }
}
