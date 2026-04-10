//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import * as Native from '../Native.js';
import { Aci } from '../Address.js';
import { PublicKey } from '../EcKeys.js';
import { Environment, type TokioAsyncContext } from '../net.js';

// For JSDoc references
import { type UnauthenticatedChatConnection } from './Chat.js';
import {
  type KeyTransparencyError,
  type KeyTransparencyVerificationFailed,
  type ChatServiceInactive,
  type IoError,
  type RateLimitedError,
} from '../Errors.js';

/**
 * Interface of a local persistent key transparency data store.
 *
 * Contents of the store are opaque to the client and are only supposed to be
 * used by the {@link Client}.
 */
export interface Store {
  getLastDistinguishedTreeHead: () => Promise<Uint8Array<ArrayBuffer> | null>;
  setLastDistinguishedTreeHead: (
    bytes: Readonly<Uint8Array<ArrayBuffer>> | null
  ) => Promise<void>;

  getAccountData: (aci: Aci) => Promise<Uint8Array<ArrayBuffer> | null>;
  setAccountData: (
    aci: Aci,
    bytes: Readonly<Uint8Array<ArrayBuffer>>
  ) => Promise<void>;
}

/**
 * Options that are accepted by all {@link Client} APIs.
 *
 * abortSignal, if present, can be used to cancel long-running network IO.
 */
export type Options = { abortSignal?: AbortSignal };

/**
 * ACI descriptor for key transparency requests.
 */
export type AciInfo = { aci: Aci; identityKey: PublicKey };

/**
 * E.164 descriptor for key transparency requests.
 */
export type E164Info = {
  e164: string;
  unidentifiedAccessKey: Readonly<Uint8Array<ArrayBuffer>>;
};

/**
 * Key transparency client request
 *
 * Always use latest known values of all identifiers (ACI, E.164, username hash)
 * associated with the account searched for/monitored, along with a correct
 * value of {@link CheckMode}.
 *
 */
export type Request = CheckMode & {
  /** ACI information for the request. Required. */
  aciInfo: AciInfo;
  /** Unidentified access key associated with the account. Optional. */
  e164Info?: E164Info;
  /* Hash of the username associated with the account. Optional. */
  usernameHash?: Readonly<Uint8Array<ArrayBuffer>>;
};

/**
 * The behavior of both {@link Client#check} differs depending on whether it is
 * performed for the owner of the account or contact and in the former case whether
 * the phone number discoverability is enabled.
 *
 * For example, if the newer version of account data is found in the key
 * transparency log while monitoring "self", it will terminate with an error.
 * However, the same check for a "contact" will result in a follow-up search
 * request.
 */
export type CheckMode =
  | { mode: 'contact' }
  | { mode: 'self'; isE164Discoverable: boolean };

/**
 * Typed API to access the key transparency subsystem using an existing
 * unauthenticated chat connection.
 *
 * Unlike {@link UnauthenticatedChatConnection}, the client does
 * not export "raw" send/receive APIs, and instead uses them internally to
 * implement high-level key transparency operations.
 *
 * See {@link ClientImpl} for the implementation details.
 *
 * Instances should be obtained by calling {@link UnauthenticatedChatConnection.keyTransparencyClient}
 *
 * Example usage:
 *
 * @example
 * ```ts
 * const network = new Net({
 *   localTestServer: false,
 *   env: Environment.Staging,
 *   userAgent: 'key-transparency-example'
 * });
 *
 * const chat = await network.connectUnauthenticatedChat({
 *   onConnectionInterrupted: (_cause) => {}
 * });
 *
 * const kt = chat.keyTransparencyClient();
 *
 * // Promise fulfillment means the operation succeeded with no further steps required.
 * await kt.check({ aciInfo: { aci: myACI, identityKey: myAciIdentityKey, mode: 'contact' } }, store);
 * ```
 *
 */
export interface Client {
  /**
   * A unified key transparency operation that performs a search, a monitor, or both.
   *
   * Caller should pass latest known values of all identifiers (ACI, E.164, username hash) associated
   * with the account, along with a correct value of {@link CheckMode}.
   *
   * If there is no data in the store for the account, the search operation will be performed. Following
   * this initial search, the monitor operation will be used.
   *
   * If any of the fields in the monitor response contain a version that is higher than the one
   * currently in the store, the behavior depends on the mode parameter value.
   * - { mode: 'self', ...} - A {@link KeyTransparencyError} will be returned, no search request will
   *   be issued.
   * - 'contact' - Another search request will be performed automatically and, if it succeeds,
   *   the updated account data will be stored.
   *
   * @param request - Key transparency client {@link Request}.
   * @param store - Local key transparency storage. It will be queried for both
   * the account data before sending the server request and, if the request
   * succeeds, will be updated with the operation results.
   * @param options - options for the asynchronous operation. Optional.
   *
   * @returns A promise that resolves if the check succeeds and the local state has been updated
   * to reflect the latest changes.
   *
   * @throws {KeyTransparencyError} for errors related to key transparency logic, which
   * includes missing required fields in the serialized data. Retrying the check without
   * changing any of the arguments (including the state of the store) is unlikely to yield a
   * different result.
   * @throws {KeyTransparencyVerificationFailed} when it fails to
   * verify the data in key transparency server response, such as an incorrect proof or a
   * wrong signature. This is also the error thrown when new version
   * of account data is found in the key transparency log when
   * checking for self. See {@link CheckMode}.
   * @throws {ChatServiceInactive} if the chat connection has been closed.
   * @throws {IoError} if an error occurred while communicating with the server.
   * @throws {RateLimitedError} if the server is rate limiting this client. This is **retryable**
   * after waiting the designated delay.
   */
  check: (
    request: Request,
    store: Store,
    options?: Readonly<Options>
  ) => Promise<void>;
}

export class ClientImpl implements Client {
  constructor(
    private readonly asyncContext: TokioAsyncContext,
    private readonly chatService: Native.Wrapper<Native.UnauthenticatedChatConnection>,
    private readonly env: Environment
  ) {}

  async check(
    request: Request,
    store: Store,
    options?: Readonly<Options>
  ): Promise<void> {
    const { abortSignal } = options ?? {};
    const {
      aciInfo: { aci, identityKey: aciIdentityKey },
      e164Info,
      usernameHash,
      mode,
    } = request;
    const { e164, unidentifiedAccessKey } = e164Info ?? {
      e164: null,
      unidentifiedAccessKey: null,
    };
    const [accountData, newDistinguished] =
      await this.asyncContext.makeCancellable(
        abortSignal,
        Native.KeyTransparency_Check(
          this.asyncContext,
          this.env,
          this.chatService,
          aci.getServiceIdFixedWidthBinary(),
          aciIdentityKey,
          e164,
          unidentifiedAccessKey,
          usernameHash ?? null,
          await store.getAccountData(aci),
          await store.getLastDistinguishedTreeHead(),
          mode === 'self',
          mode === 'self' ? request.isE164Discoverable : true
        )
      );
    await store.setAccountData(aci, accountData);
    if (newDistinguished.length > 0) {
      await store.setLastDistinguishedTreeHead(newDistinguished);
    }
  }
}
