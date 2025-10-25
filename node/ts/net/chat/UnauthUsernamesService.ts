//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { Buffer } from 'node:buffer';
import * as uuid from 'uuid';

import * as Native from '../../Native.js';
import { Aci } from '../../Address.js';
import { Uuid } from '../../uuid.js';
import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';

// For documentation
import type * as usernames from '../../usernames.js';
import type {
  InvalidEntropyDataLength,
  InvalidUsernameLinkEncryptedData,
} from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthUsernamesService {}
}

export interface UnauthUsernamesService {
  /**
   * Looks up a username hash on the service, like that computed by {@link usernames.hash}.
   *
   * Returns the corresponding account's ACI, or `null` if the username doesn't correspond to an
   * account.
   *
   * Throws / completes with failure only if the request can't be completed, potentially including
   * if the hash is structurally invalid.
   */
  lookUpUsernameHash: (
    request: {
      hash: Uint8Array;
    },
    options?: RequestOptions
  ) => Promise<Aci | null>;

  /**
   * Looks up a username link on the service by UUID.
   *
   * Returns a decrypted, validated username, or `null` if the UUID does not correspond to a
   * username link (perhaps the user rotated their link).
   *
   * Throws / completes with failure if the request can't be completed. Specifically throws
   * {@link InvalidEntropyDataLength} if the entropy is invalid, and
   * {@link InvalidUsernameLinkEncryptedData} if the data fetched from the service could not be
   * decrypted or did not contain a valid username. `uuid` should be validated ahead of time.
   */
  lookUpUsernameLink: (
    request: {
      uuid: Uuid;
      entropy: Uint8Array;
    },
    options?: RequestOptions
  ) => Promise<{ username: string; hash: Uint8Array } | null>;
}

UnauthenticatedChatConnection.prototype.lookUpUsernameHash = async function (
  {
    hash,
  }: {
    hash: Uint8Array;
  },
  options?: RequestOptions
): Promise<Aci | null> {
  const response = await this._asyncContext.makeCancellable(
    options?.abortSignal,
    Native.UnauthenticatedChatConnection_look_up_username_hash(
      this._asyncContext,
      this._chatService,
      Buffer.from(hash)
    )
  );
  return response ? Aci.fromUuidBytes(response) : null;
};

UnauthenticatedChatConnection.prototype.lookUpUsernameLink = async function (
  {
    uuid: linkUuid,
    entropy,
  }: {
    uuid: Uuid;
    entropy: Uint8Array;
  },
  options?: RequestOptions
): Promise<{ username: string; hash: Uint8Array } | null> {
  const response = await this._asyncContext.makeCancellable(
    options?.abortSignal,
    Native.UnauthenticatedChatConnection_look_up_username_link(
      this._asyncContext,
      this._chatService,
      uuid.parse(linkUuid),
      entropy
    )
  );
  return response ? { username: response[0], hash: response[1] } : null;
};
