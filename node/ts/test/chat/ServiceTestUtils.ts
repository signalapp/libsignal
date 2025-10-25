//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { TokioAsyncContext, UnauthenticatedChatConnection } from '../../net.js';
import { FakeChatRemote } from '../../net/FakeChat';

/**
 * A requirement that `Sub` not contain any properties that aren't in `Super`, or properties with
 * different types.
 *
 * Use {@link PickSubset} to generate a type that a `Super` instance can be assigned to. This will
 * be equivalent to `Sub` in practice, but TypeScript can only figure that out in concrete contexts.
 */
type Subset<Super, Sub> = Partial<Super> & {
  [K in Exclude<keyof Sub, keyof Super>]: never;
};

/** See {@link Subset}. */
type PickSubset<Super, Sub extends Subset<Super, Sub>> = Pick<
  Super,
  keyof Super & keyof Sub
>;

/**
 * Makes an unauth connection with a fake remote, but forces the caller to specify which APIs they
 * need from the connection.
 */
export function connectUnauth<
  // The default of `object` forces the caller to provide a type explicitly to access any members of
  // the result.
  Api extends Subset<UnauthenticatedChatConnection, Api> = object
>(
  tokio: TokioAsyncContext
): [PickSubset<UnauthenticatedChatConnection, Api>, FakeChatRemote] {
  return UnauthenticatedChatConnection.fakeConnect(tokio, {
    onConnectionInterrupted: () => {},
    onIncomingMessage: () => {},
    onQueueEmpty: () => {},
  });
}
