//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../../../Native';
import { Aci } from '../../Address';
import { RequestOptions, UnauthenticatedChatConnection } from '../Chat';

// For documentation
import type * as usernames from '../../usernames';

declare module '../Chat' {
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
  lookUpUsernameHash(
    request: {
      hash: Uint8Array;
    },
    options?: RequestOptions
  ): Promise<Aci | null>;
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
